/**
 * The finished backups in `backups/`: listing, downloading and deleting them.
 *
 * Every operation that takes a name matches it against the listing rather than
 * joining it onto the directory, so a name like `../.env` from a query string
 * can never reach a file the list would not show.
 */
import { join } from "jsr:@std/path@1";
import { ARCHIVE_EXTENSION } from "./archive.ts";

/** Where backups are written, relative to the project directory. */
export const BACKUPS_DIR = "backups";

/** A finished backup, as the dashboard lists it. */
export interface BackupFile {
  name: string;
  bytes: number;
  createdAt: string;
  encrypted: boolean;
}

/**
 * When a backup was started, from the UTC minute in its name, or null for a
 * name that carries none.
 *
 * Preferred over the file's mtime, which a copy with scp or a restore resets to
 * the moment of copying — an old backup copied back in would otherwise count
 * as the newest, and the newest is what gets kept.
 */
export function startedAt(name: string): Date | null {
  const match = name.match(/^rift-backup-(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})/);
  if (!match) return null;
  const [, year, month, day, hour, minute] = match.map(Number);
  const at = new Date(Date.UTC(year, month - 1, day, hour, minute));
  return Number.isNaN(at.getTime()) ? null : at;
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
        createdAt: (startedAt(entry.name) ?? info.mtime ?? new Date(0)).toISOString(),
        encrypted: entry.name.endsWith(`-encrypted${ARCHIVE_EXTENSION}`),
      });
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  // Names break ties within one minute, so the order never depends on the
  // order the directory happened to be read in.
  return found.sort((a, b) =>
    b.createdAt.localeCompare(a.createdAt) || b.name.localeCompare(a.name)
  );
}

/** One backup, opened for download, or null when [name] is not one. */
export async function openBackup(
  projectDir: string,
  name: string,
): Promise<{ file: Deno.FsFile; bytes: number } | null> {
  const found = await find(projectDir, name);
  if (!found) return null;
  const file = await Deno.open(join(projectDir, BACKUPS_DIR, found.name));
  return { file, bytes: (await file.stat()).size };
}

/** Delete one backup. False when [name] is not one. */
export async function deleteBackup(projectDir: string, name: string): Promise<boolean> {
  const found = await find(projectDir, name);
  if (!found) return false;
  await Deno.remove(join(projectDir, BACKUPS_DIR, found.name));
  return true;
}

/**
 * Delete all but the newest [keep] backups, and name the ones deleted.
 *
 * Zero keeps everything rather than nothing: it is the setting that turns
 * scheduled backups off, and a backup made by hand on such a server is one
 * somebody wants.
 */
export async function pruneBackups(projectDir: string, keep: number): Promise<string[]> {
  if (keep <= 0) return [];
  const doomed = (await listBackups(projectDir)).slice(keep);
  for (const file of doomed) {
    await Deno.remove(join(projectDir, BACKUPS_DIR, file.name));
  }
  return doomed.map((file) => file.name);
}

async function find(projectDir: string, name: string): Promise<BackupFile | undefined> {
  return (await listBackups(projectDir)).find((backup) => backup.name === name);
}
