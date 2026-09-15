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
import { BACKUPS_DIR, listBackups, pruneBackups } from "./files.ts";
import { parseSchedule } from "./schedule.ts";

/** How one backup ended. */
export interface BackupOutcome {
  file?: string;
  bytes?: number;
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
