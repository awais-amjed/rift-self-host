/**
 * Bringing a server back from a backup file extracted beside the compose file.
 *
 * Runs from the console's start (boot.ts), at the one point a restore can
 * safely happen: the stack is up, and the database has no Rift schema at all.
 * Anything else — a database with data in it — is never overwritten by a
 * backup that happens to be lying in the folder.
 */
import { join } from "jsr:@std/path@1";
import { execFromFile, restartStackServices, waitForSettled } from "../docker.ts";
import {
  ATTACHMENT_DIR,
  ATTACHMENT_INDEX,
  DATABASE_DUMP,
  MANIFEST,
  PAYLOAD_DIR,
  SEALED_FILE,
  STORAGE_ARCHIVE,
  unsealInto,
} from "./archive.ts";
import {
  parseIndex,
  putAttachmentsBack,
  STORAGE_VOLUME,
  unsealAttachments,
} from "./attachments.ts";

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

/** An encrypted backup waiting for its passphrase. */
export function sealedBackupPresent(projectDir: string): Promise<boolean> {
  return exists(join(projectDir, SEALED_FILE));
}

/** A backup in the clear, ready to load. */
export async function backupPresent(projectDir: string): Promise<boolean> {
  return await exists(join(projectDir, MANIFEST)) &&
    await exists(join(projectDir, DATABASE_DUMP));
}

/**
 * Decrypt the backup beside the compose file into `.env` and `backup/`, and
 * each of its attachments where it lies.
 *
 * The sealed file is removed once opened: the folder then looks exactly like
 * an unencrypted backup, and the console's next step is the same for both.
 */
export async function openSealedBackup(
  projectDir: string,
  passphrase: string,
): Promise<void> {
  const sealed = join(projectDir, SEALED_FILE);
  await unsealInto(sealed, passphrase, projectDir);
  const failed = await unsealAttachments(join(projectDir, ATTACHMENT_DIR), passphrase);
  if (failed.length > 0) {
    console.error(`${failed.length} attachments in the backup did not decrypt.`);
  }
  await Deno.remove(sealed);
}

/** What loading a backup found. */
export interface RestoreResult {
  /** ERROR lines psql printed. Zero on a backup the console made. */
  databaseErrors: string[];
  /** Attachments left out: their file in the backup is damaged or gone. */
  lostAttachments: string[];
}

/**
 * Load the backup's database and attachments, then restart the stack.
 *
 * The payload folder is renamed afterwards, so a database emptied again later
 * is not silently refilled from a months-old backup still sitting there.
 */
export async function restoreFromBackup(
  projectDir: string,
  report: (step: string) => void,
): Promise<RestoreResult> {
  report("Loading the database");
  // bash with pipefail: a dump that fails to decompress halfway must fail
  // loudly, not load the half it got.
  const database = await execFromFile(
    "db",
    ["bash", "-o", "pipefail", "-c", "gunzip | psql -q -U supabase_admin postgres"],
    join(projectDir, DATABASE_DUMP),
  );
  if (database.code !== 0) {
    throw new Error(
      `The database did not load: ${database.stderr.split("\n").filter(Boolean).at(-1)}`,
    );
  }
  const databaseErrors = database.stderr.split("\n").filter((line) =>
    line.includes("ERROR")
  );

  let lostAttachments: string[] = [];
  if (await exists(join(projectDir, ATTACHMENT_INDEX))) {
    report("Putting the attachments back");
    if (!await exists(STORAGE_VOLUME)) {
      throw new Error(
        "The console cannot see storage's volume, so the attachments cannot go back. " +
          "Use the docker-compose.yml that came with the backup.",
      );
    }
    const put = await putAttachmentsBack(
      join(projectDir, ATTACHMENT_DIR),
      parseIndex(await Deno.readTextFile(join(projectDir, ATTACHMENT_INDEX))),
      STORAGE_VOLUME,
    );
    lostAttachments = [...put.damaged, ...put.missing];
  } else if (await exists(join(projectDir, STORAGE_ARCHIVE))) {
    report("Putting the attachments back");
    const storage = await execFromFile(
      "storage",
      ["tar", "xzf", "-", "-C", "/var/lib/storage"],
      join(projectDir, STORAGE_ARCHIVE),
    );
    if (storage.code !== 0) {
      throw new Error(
        `The attachments did not unpack: ${storage.stderr.split("\n").at(-1)}`,
      );
    }
  }

  report("Restarting the stack");
  const restarted = await restartStackServices();
  if (!restarted.ok) throw new Error(`The stack did not restart: ${restarted.stderr}`);
  await waitForSettled();

  await Deno.rename(
    join(projectDir, PAYLOAD_DIR),
    join(projectDir, `${PAYLOAD_DIR}.restored`),
  );
  return { databaseErrors, lostAttachments };
}
