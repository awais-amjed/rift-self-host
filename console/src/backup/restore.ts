/**
 * Bringing a server back from a backup file extracted beside the compose file.
 *
 * Runs from the console's start (boot.ts), at the one point a restore can
 * safely happen: the stack is up, and the database has no Rift schema at all.
 * Anything else — a database with data in it — is never overwritten by a
 * backup that happens to be lying in the folder.
 */
import { dirname, join } from "jsr:@std/path@1";
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

/** Where a sealed backup is opened before anything of it is put in place. */
export const STAGING_DIR = ".restore-staging";

/**
 * Decrypt the backup beside the compose file into `.env` and `backup/`, and
 * each of its attachments where it lies.
 *
 * The sealed part is opened into a folder of its own first and moved into
 * place only once all of it has opened, `.env` last. `.env` is what makes the
 * console count as set up, and it used to land first: a file cut short by a
 * bad copy left a server that refused another restore, with half a dump
 * beside it. Stopped anywhere before `.env`, the page asks for the passphrase
 * again and this starts over; attachments already decrypted are skipped.
 *
 * The sealed file is removed once everything is in place: the folder then
 * looks exactly like an unencrypted backup, and the console's next step is
 * the same for both.
 */
export async function openSealedBackup(
  projectDir: string,
  passphrase: string,
): Promise<void> {
  const sealed = join(projectDir, SEALED_FILE);
  const staging = join(projectDir, STAGING_DIR);
  await Deno.remove(staging, { recursive: true }).catch(() => {});
  await Deno.mkdir(staging, { mode: 0o700 });

  const written = await unsealInto(sealed, passphrase, staging);
  const failed = await unsealAttachments(join(projectDir, ATTACHMENT_DIR), passphrase);
  if (failed.length > 0) {
    console.error(`${failed.length} attachments in the backup did not decrypt.`);
  }

  const last = written.filter((path) => path === ".env");
  for (const path of [...written.filter((path) => path !== ".env"), ...last]) {
    await Deno.mkdir(dirname(join(projectDir, path)), { recursive: true });
    await Deno.rename(join(staging, path), join(projectDir, path));
  }
  await Deno.remove(sealed);
  await Deno.remove(staging, { recursive: true }).catch(() => {});
}

/** What loading a backup found. */
export interface RestoreResult {
  /** ERROR lines psql printed. Zero on a backup the console made. */
  databaseErrors: string[];
  /** Attachments left out: their file in the backup is damaged or gone. */
  lostAttachments: string[];
}

/** Written before the database loads, and gone with `backup/` once all is done. */
export const RESTORE_MARKER = `${PAYLOAD_DIR}/.restoring`;

/**
 * Whether a restore was under way when the console stopped: the marker is
 * there, so the database may be in and the attachments not.
 */
export function restoreInterrupted(projectDir: string): Promise<boolean> {
  return exists(join(projectDir, RESTORE_MARKER));
}

/**
 * What runs before the dump, in the same transaction.
 *
 * A backup loads into a fresh Supabase database, whose default privileges hand
 * every new table, sequence and function in `public` (and a few more schemas)
 * to `anon` and `authenticated`. pg_dump writes an object's grants as they
 * differ from Postgres' own defaults, not Supabase's, so nothing in the dump
 * took those back: a restored server let anybody with the publishable key call
 * every service-only function and write any column a policy allowed (measured
 * Nov 25 2026: 90 functions and 49 tables, against none on the server the
 * backup came from). So every default privilege is cleared first; the dump's
 * own `ALTER DEFAULT PRIVILEGES` lines, which come last, put them back as the
 * server had them. Migration 045 repairs a server restored before this.
 */
export const CLEAR_DEFAULT_PRIVILEGES = `DO $$
DECLARE d RECORD; g TEXT;
BEGIN
  FOR d IN SELECT pg_get_userbyid(a.defaclrole) AS owner, a.defaclnamespace AS ns,
                  CASE a.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                    WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS'
                  END AS kind,
                  a.defaclacl AS acl
             FROM pg_default_acl a LOOP
    FOR g IN SELECT DISTINCT CASE WHEN x.grantee = 0 THEN 'PUBLIC'
                                  ELSE quote_ident(pg_get_userbyid(x.grantee)) END
               FROM aclexplode(d.acl) x LOOP
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I %s REVOKE ALL ON %s FROM %s',
        d.owner,
        CASE WHEN d.ns = 0 THEN '' ELSE 'IN SCHEMA ' || quote_ident(d.ns::regnamespace::text) END,
        d.kind, g);
    END LOOP;
  END LOOP;
END $$;`;

/**
 * Load the database in one transaction, after [CLEAR_DEFAULT_PRIVILEGES].
 *
 * One transaction with ON_ERROR_STOP, so a load either lands whole or not at
 * all: nothing of it is visible to the API while tables hold rows and their
 * row security is not yet on (pg_dump turns it on after the data), and a dump
 * that fails partway leaves an empty database to try again, not half a server
 * that the next start takes for a finished one.
 */
export function loadArgs(): string[] {
  return [
    "bash",
    "-o",
    "pipefail",
    "-c",
    `{ printf '%s\\n' "$1"; gunzip; } | psql -q -1 -v ON_ERROR_STOP=1 -U supabase_admin postgres`,
    "restore",
    CLEAR_DEFAULT_PRIVILEGES,
  ];
}

/** Read the whole of a gzip file, throwing if it is damaged or cut short. */
export async function checkGzip(path: string): Promise<void> {
  try {
    await (await Deno.open(path)).readable
      .pipeThrough(new DecompressionStream("gzip"))
      .pipeTo(new WritableStream());
  } catch (error) {
    throw new Error(
      "The backup's database file is damaged or incomplete, so nothing was loaded " +
        `(${error instanceof Error ? error.message : String(error)}).`,
    );
  }
}

/**
 * Load the backup's database and attachments, then restart the stack.
 *
 * [databaseLoaded] when a restore that stopped after the database is being
 * finished ([restoreInterrupted]): the load already committed.
 *
 * The payload folder is renamed afterwards, so a database emptied again later
 * is not silently refilled from a months-old backup still sitting there; an
 * encrypted backup's is deleted instead, since in the clear it would hold the
 * database and `.env` that the passphrase was protecting.
 */
export async function restoreFromBackup(
  projectDir: string,
  report: (step: string) => void,
  options: { databaseLoaded?: boolean } = {},
): Promise<RestoreResult> {
  let databaseErrors: string[] = [];
  if (!options.databaseLoaded) {
    report("Checking the backup");
    await checkGzip(join(projectDir, DATABASE_DUMP));
    await Deno.writeTextFile(join(projectDir, RESTORE_MARKER), new Date().toISOString());

    report("Loading the database");
    const database = await execFromFile(
      "db",
      loadArgs(),
      join(projectDir, DATABASE_DUMP),
    );
    databaseErrors = database.stderr.split("\n").filter((line) => line.includes("ERROR"));
    if (database.code !== 0) {
      throw new Error(
        `The database did not load, and nothing of it was kept: ${
          databaseErrors[0] ?? database.stderr.split("\n").filter(Boolean).at(-1)
        }`,
      );
    }
  }

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

  const payload = join(projectDir, PAYLOAD_DIR);
  if (await wasEncrypted(projectDir)) {
    await Deno.remove(payload, { recursive: true });
  } else {
    await Deno.rename(payload, join(projectDir, `${PAYLOAD_DIR}.restored`));
  }
  return { databaseErrors, lostAttachments };
}

async function wasEncrypted(projectDir: string): Promise<boolean> {
  try {
    return JSON.parse(await Deno.readTextFile(join(projectDir, MANIFEST))).encrypted ===
      true;
  } catch {
    return false;
  }
}
