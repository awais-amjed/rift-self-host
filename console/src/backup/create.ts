/**
 * Making a backup from the dashboard.
 *
 * Written to `backups/` beside the compose file first, and downloadable from
 * there afterwards: a download goes through the SSH tunnel and a browser tab,
 * and stops when either does, so it is never the only copy being made. The
 * trade is that the file starts on the same disk as the server, which the
 * dashboard says out loud.
 *
 * The database is dumped inside its own container and the attachments are
 * packed inside theirs, both streamed straight to disk, so neither is ever
 * held in the console's memory. The attachments are packed with busybox tar,
 * which drops their extended attributes; that is deliberate, because the
 * console writes those back from the database on every start (see
 * storage_repair.ts) and nothing is lost.
 */
import { join } from "jsr:@std/path@1";
import { execToFile } from "../docker.ts";
import { readEnvFile } from "../env_file.ts";
import { imageVersion } from "../state.ts";
import {
  ARCHIVE_EXTENSION,
  backupName,
  DATABASE_DUMP,
  MANIFEST,
  type Manifest,
  restoreInstructions,
  STORAGE_ARCHIVE,
  writeArchive,
} from "./archive.ts";

/** Where backups are written, relative to the project directory. */
export const BACKUPS_DIR = "backups";

/** A finished backup, as the dashboard lists it. */
export interface BackupFile {
  name: string;
  bytes: number;
  createdAt: string;
  encrypted: boolean;
}

/** What the dashboard polls. */
export interface BackupStatus {
  /** The step running now, or null when nothing is. */
  running: string | null;
  last: { file?: string; bytes?: number; error?: string; finishedAt: string } | null;
}

let running: string | null = null;
let last: BackupStatus["last"] = null;

export function backupStatus(): BackupStatus {
  return { running, last };
}

/** Start a backup in the background. Throws if one is already running. */
export function startBackup(projectDir: string, passphrase: string): void {
  if (running !== null) throw new Error("A backup is already being made.");
  running = "Starting";
  void makeBackup(projectDir, passphrase.length > 0 ? passphrase : undefined)
    .then((result) => {
      last = { ...result, finishedAt: new Date().toISOString() };
    })
    .catch((error) => {
      console.error("[backup]", error);
      last = {
        error: error instanceof Error ? error.message : String(error),
        finishedAt: new Date().toISOString(),
      };
    })
    .finally(() => {
      running = null;
    });
}

async function dump(service: string, command: string[], path: string, what: string) {
  const result = await execToFile(service, command, path);
  if (result.code !== 0) {
    const reason = result.stderr.split("\n").filter(Boolean).at(-1) ?? "no reason given";
    throw new Error(`Could not ${what}: ${reason}`);
  }
}

async function makeBackup(
  projectDir: string,
  passphrase: string | undefined,
): Promise<{ file: string; bytes: number }> {
  const now = new Date();
  const encrypted = passphrase !== undefined;
  // Never the name of a backup already there: renaming over it would replace a
  // good backup with this one before anyone noticed.
  const taken = new Set(
    (await listBackups(projectDir)).map((file) =>
      file.name.slice(0, -ARCHIVE_EXTENSION.length)
    ),
  );
  let sequence = 1;
  let name = backupName(now, encrypted, sequence);
  while (taken.has(name)) name = backupName(now, encrypted, ++sequence);
  const directory = join(projectDir, BACKUPS_DIR);
  const work = join(directory, `.${name}.working`);
  const partial = join(directory, `${name}${ARCHIVE_EXTENSION}.partial`);
  const final = join(directory, `${name}${ARCHIVE_EXTENSION}`);
  await Deno.mkdir(join(work, "backup"), { recursive: true, mode: 0o700 });

  try {
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
      join(work, DATABASE_DUMP),
      "dump the database",
    );

    running = "Packing the attachments";
    await dump(
      "storage",
      ["tar", "czf", "-", "-C", "/var/lib/storage", "."],
      join(work, STORAGE_ARCHIVE),
      "pack the attachments",
    );

    const manifest: Manifest = {
      format: 1,
      createdAt: now.toISOString(),
      consoleVersion: imageVersion(),
      domain: readEnvFile(projectDir).RIFT_DOMAIN ?? "",
      encrypted: passphrase !== undefined,
    };
    await Deno.writeTextFile(join(work, MANIFEST), JSON.stringify(manifest, null, 2));

    running = passphrase ? "Encrypting and writing the file" : "Writing the file";
    await writeArchive({
      destination: partial,
      name,
      composeFile: join(projectDir, "docker-compose.yml"),
      instructions: restoreInstructions(manifest, name),
      payload: {
        ".env": join(projectDir, ".env"),
        [MANIFEST]: join(work, MANIFEST),
        [DATABASE_DUMP]: join(work, DATABASE_DUMP),
        [STORAGE_ARCHIVE]: join(work, STORAGE_ARCHIVE),
      },
      passphrase,
      workDir: work,
    });
    await Deno.chmod(partial, 0o600);
    await Deno.rename(partial, final);

    return {
      file: `${BACKUPS_DIR}/${name}${ARCHIVE_EXTENSION}`,
      bytes: (await Deno.stat(final)).size,
    };
  } finally {
    await Deno.remove(work, { recursive: true }).catch(() => {});
    await Deno.remove(partial).catch(() => {});
  }
}

/** The backups in `backups/`, newest first. */
export async function listBackups(projectDir: string): Promise<BackupFile[]> {
  const directory = join(projectDir, BACKUPS_DIR);
  const found: BackupFile[] = [];
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (!entry.isFile || !entry.name.startsWith("rift-backup-")) continue;
      if (!entry.name.endsWith(ARCHIVE_EXTENSION)) continue;
      const info = await Deno.stat(join(directory, entry.name));
      found.push({
        name: entry.name,
        bytes: info.size,
        createdAt: (info.mtime ?? new Date(0)).toISOString(),
        encrypted: entry.name.endsWith(`-encrypted${ARCHIVE_EXTENSION}`),
      });
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return found.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/**
 * One backup from `backups/`, opened for download, or null when [name] is not
 * one. Matched against the listing rather than joined onto the directory, so a
 * name like `../.env` can never reach a file the list would not show.
 */
export async function openBackup(
  projectDir: string,
  name: string,
): Promise<{ file: Deno.FsFile; bytes: number } | null> {
  const found = (await listBackups(projectDir)).find((backup) => backup.name === name);
  if (!found) return null;
  const file = await Deno.open(join(projectDir, BACKUPS_DIR, found.name));
  return { file, bytes: (await file.stat()).size };
}
