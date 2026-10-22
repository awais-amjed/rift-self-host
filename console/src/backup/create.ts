/**
 * Making a backup from the dashboard.
 *
 * Written to `backups/` beside the compose file first, and downloadable from
 * there afterwards: a download goes through the SSH tunnel and a browser tab,
 * and stops when either does, so it is never the only copy being made. The
 * trade is that the backup starts on the same disk as the server, which the
 * dashboard says out loud.
 *
 * The database is dumped inside its own container, streamed straight to disk.
 * The attachments are read from storage's volume, which the console mounts,
 * and each one the previous backup of the same kind already holds is shared
 * with it rather than copied (attachments.ts). Only the bytes are kept, not
 * the extended attributes storage keeps beside them; that is deliberate,
 * because the console writes those back from the database on every start
 * (see storage_repair.ts) and nothing is lost.
 */
import { join } from "jsr:@std/path@1";
import { execToFile } from "../docker.ts";
import { readEnvFile } from "../env_file.ts";
import { imageVersion } from "../state.ts";
import {
  ARCHIVE_EXTENSION,
  ATTACHMENT_DIR,
  ATTACHMENT_INDEX,
  backupName,
  DATABASE_DUMP,
  MANIFEST,
  type Manifest,
  readSealedIndex,
  restoreInstructions,
  SEALED_FILE,
  sealPayload,
} from "./archive.ts";
import {
  collectAttachments,
  formatIndex,
  parseIndex,
  type PreviousAttachments,
  STORAGE_VOLUME,
} from "./attachments.ts";
import { type BackupFile, BACKUPS_DIR, listBackups, pruneBackups } from "./files.ts";
import { parseSchedule } from "./schedule.ts";
import { deriveSealKey } from "./seal.ts";

/** How one backup ended. */
export interface BackupOutcome {
  file?: string;
  bytes?: number;
  /** Attachments new in this backup, and their size; the rest are shared. */
  copied?: number;
  copiedBytes?: number;
  shared?: number;
  error?: string;
  scheduled: boolean;
  /** Older backups deleted afterwards, to keep the number set. */
  pruned: string[];
  /** Why deleting older backups failed. The backup itself is still good. */
  pruneError?: string;
  finishedAt: string;
}

/** What the dashboard polls. */
export interface BackupStatus {
  /** The step running now, or null when nothing is. */
  running: string | null;
  last: BackupOutcome | null;
  lastScheduled: BackupOutcome | null;
}

let running: string | null = null;
let last: BackupOutcome | null = null;
let lastScheduled: BackupOutcome | null = null;

export function backupStatus(): BackupStatus {
  return { running, last, lastScheduled };
}

/**
 * Start a backup in the background. Throws if one is already running.
 *
 * Once it is safely written, older backups beyond the number to keep are
 * deleted — only then, so a server whose backups have started failing keeps
 * the last good ones instead of trading them for nothing.
 */
export function startBackup(
  projectDir: string,
  passphrase: string,
  scheduled = false,
): void {
  if (running !== null) throw new Error("A backup is already being made.");
  running = "Starting";
  const finish = (outcome: Omit<BackupOutcome, "scheduled" | "finishedAt">) => {
    last = { ...outcome, scheduled, finishedAt: new Date().toISOString() };
    if (scheduled) lastScheduled = last;
  };
  void makeBackup(projectDir, passphrase.length > 0 ? passphrase : undefined)
    .then(async (result) => {
      running = "Deleting older backups";
      const { schedule, problem } = parseSchedule(readEnvFile(projectDir));
      try {
        if (problem !== null) throw new Error(problem);
        finish({ ...result, pruned: await pruneBackups(projectDir, schedule.keep) });
      } catch (error) {
        console.error("[backup] deleting older backups:", error);
        finish({ ...result, pruned: [], pruneError: messageOf(error) });
      }
    })
    .catch((error) => {
      console.error("[backup]", error);
      finish({ error: messageOf(error), pruned: [] });
    })
    .finally(() => {
      running = null;
    });
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function dump(service: string, command: string[], path: string, what: string) {
  const result = await execToFile(service, command, path);
  if (result.code !== 0) {
    const reason = result.stderr.split("\n").filter(Boolean).at(-1) ?? "no reason given";
    throw new Error(`Could not ${what}: ${reason}`);
  }
}

/**
 * The newest finished backup folder of the same kind, to share attachments
 * with. An encrypted one counts only if [passphrase] opens it: its files are
 * sealed, and one sealed under another passphrase would not open with this.
 */
async function previousAttachments(
  projectDir: string,
  backups: BackupFile[],
  passphrase: string | undefined,
): Promise<PreviousAttachments | null> {
  const encrypted = passphrase !== undefined;
  const previous = backups.find((backup) =>
    backup.folder && backup.encrypted === encrypted
  );
  if (!previous) return null;
  const folder = join(projectDir, BACKUPS_DIR, previous.name);
  try {
    const index = passphrase === undefined
      ? await Deno.readTextFile(join(folder, ATTACHMENT_INDEX))
      : await readSealedIndex(join(folder, SEALED_FILE), passphrase);
    if (index === null) return null;
    return { directory: join(folder, ATTACHMENT_DIR), entries: parseIndex(index) };
  } catch (error) {
    // Nothing to share is only slower: every attachment is copied afresh.
    console.error(`[backup] not sharing with ${previous.name}:`, error);
    return null;
  }
}

/**
 * What a backup interrupted by the console stopping left behind: one runs at
 * a time, so any found when starting another is dead, and can hold gigabytes.
 */
async function removeLeftovers(directory: string): Promise<void> {
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (/^\.rift-backup-.+\.(working|scratch)$/.test(entry.name)) {
        await Deno.remove(join(directory, entry.name), { recursive: true });
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
}

async function makeBackup(
  projectDir: string,
  passphrase: string | undefined,
): Promise<{
  file: string;
  bytes: number;
  copied: number;
  copiedBytes: number;
  shared: number;
}> {
  const now = new Date();
  const encrypted = passphrase !== undefined;
  try {
    await Deno.stat(STORAGE_VOLUME);
  } catch {
    throw new Error(
      "The console cannot see the attachments. Its docker-compose.yml is missing " +
        "the line that lends it storage's volume: update to the compose file of " +
        "this release.",
    );
  }
  const backups = await listBackups(projectDir);
  // Never the name of a backup already there: renaming over it would replace a
  // good backup with this one before anyone noticed.
  const taken = new Set(
    backups.map((file) =>
      file.folder ? file.name : file.name.slice(0, -ARCHIVE_EXTENSION.length)
    ),
  );
  let sequence = 1;
  let name = backupName(now, encrypted, sequence);
  while (taken.has(name)) name = backupName(now, encrypted, ++sequence);
  const directory = join(projectDir, BACKUPS_DIR);
  await removeLeftovers(directory);
  const work = join(directory, `.${name}.working`);
  const scratch = join(directory, `.${name}.scratch`);
  const final = join(directory, name);
  await Deno.mkdir(join(work, ATTACHMENT_DIR), { recursive: true, mode: 0o700 });
  await Deno.mkdir(scratch, { recursive: true, mode: 0o700 });
  await Deno.chmod(work, 0o700);

  try {
    // Sealed parts go to scratch first and are sealed into the backup; in the
    // clear they are written where they will stay.
    const at = (path: string) => join(encrypted ? scratch : work, path);
    await Deno.mkdir(at("backup"), { recursive: true, mode: 0o700 });

    running = "Dumping the database";
    await dump(
      "db",
      [
        "pg_dump",
        "-U",
        "supabase_admin",
        "--clean",
        "--if-exists",
        "-Z",
        "6",
        "postgres",
      ],
      at(DATABASE_DUMP),
      "dump the database",
    );

    running = "Copying new attachments";
    const seal = passphrase === undefined ? undefined : await deriveSealKey(passphrase);
    const collected = await collectAttachments({
      source: STORAGE_VOLUME,
      destination: join(work, ATTACHMENT_DIR),
      previous: await previousAttachments(projectDir, backups, passphrase),
      seal,
    });
    await Deno.writeTextFile(at(ATTACHMENT_INDEX), formatIndex(collected.entries), {
      mode: 0o600,
    });

    const manifest: Manifest = {
      format: 2,
      createdAt: now.toISOString(),
      consoleVersion: imageVersion(),
      domain: readEnvFile(projectDir).RIFT_DOMAIN ?? "",
      encrypted,
    };
    await Deno.writeTextFile(at(MANIFEST), JSON.stringify(manifest, null, 2), {
      mode: 0o600,
    });
    await Deno.copyFile(join(projectDir, ".env"), at(".env"));
    await Deno.chmod(at(".env"), 0o600);

    running = encrypted ? "Encrypting and writing the backup" : "Writing the backup";
    if (seal) {
      await sealPayload(
        {
          [MANIFEST]: at(MANIFEST),
          [ATTACHMENT_INDEX]: at(ATTACHMENT_INDEX),
          ".env": at(".env"),
          [DATABASE_DUMP]: at(DATABASE_DUMP),
        },
        join(work, SEALED_FILE),
        seal,
      );
    }
    await Deno.copyFile(
      join(projectDir, "docker-compose.yml"),
      join(work, "docker-compose.yml"),
    );
    await Deno.writeTextFile(
      join(work, "RESTORE.txt"),
      restoreInstructions(manifest, name),
    );
    await Deno.rename(work, final);

    const listed = (await listBackups(projectDir)).find((backup) => backup.name === name);
    return {
      file: `${BACKUPS_DIR}/${name}`,
      bytes: listed?.bytes ?? 0,
      copied: collected.copied,
      copiedBytes: collected.copiedBytes,
      shared: collected.linked,
    };
  } finally {
    await Deno.remove(work, { recursive: true }).catch(() => {});
    await Deno.remove(scratch, { recursive: true }).catch(() => {});
  }
}
