/**
 * The finished backups in `backups/`: listing, downloading and deleting them.
 *
 * A backup is a folder (archive.ts), or a `.tar.gz` file from before folders.
 * Folders share their attachments through hard links, so their sizes add up
 * to more than the disk holds; [diskUsage] counts each file once.
 *
 * Every operation that takes a name matches it against the listing rather than
 * joining it onto the directory, so a name like `../.env` from a query string
 * can never reach a file the list would not show.
 */
import { join } from "jsr:@std/path@1";
import {
  ARCHIVE_EXTENSION,
  DOWNLOAD_EXTENSION,
  folderTar,
  folderTarStream,
} from "./archive.ts";

/** Where backups are written, relative to the project directory. */
export const BACKUPS_DIR = "backups";

/** A finished backup, as the dashboard lists it. */
export interface BackupFile {
  /** The folder's name, or the old file's with its extension. */
  name: string;
  /** What downloading it gives. */
  bytes: number;
  /** A folder, rather than a file from before folders. */
  folder: boolean;
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

/** The `-2` in `rift-backup-2026-09-15-1203-2`: 1 for the minute's first. */
function sequenceOf(name: string): number {
  const match = name.match(/^rift-backup-\d{4}-\d{2}-\d{2}-\d{4}-(\d+)(?:-|\.|$)/);
  return match ? Number(match[1]) : 1;
}

/** The backups in `backups/`, newest first. */
export async function listBackups(projectDir: string): Promise<BackupFile[]> {
  const directory = join(projectDir, BACKUPS_DIR);
  const found: BackupFile[] = [];
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (!entry.name.startsWith("rift-backup-")) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory) {
        const info = await Deno.stat(path);
        found.push({
          name: entry.name,
          bytes: await folderBytes(path, entry.name),
          folder: true,
          createdAt: (startedAt(entry.name) ?? info.mtime ?? new Date(0)).toISOString(),
          encrypted: entry.name.endsWith("-encrypted"),
        });
      } else if (entry.isFile && entry.name.endsWith(ARCHIVE_EXTENSION)) {
        const info = await Deno.stat(path);
        found.push({
          name: entry.name,
          bytes: info.size,
          folder: false,
          createdAt: (startedAt(entry.name) ?? info.mtime ?? new Date(0)).toISOString(),
          encrypted: entry.name.endsWith(`-encrypted${ARCHIVE_EXTENSION}`),
        });
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  // Within one minute the `-2`, `-3`… say which came later, and then names
  // break ties, so the order never depends on the order the directory
  // happened to be read in. Comparing names alone put `-encrypted` after
  // `-2-encrypted`, though it was made first.
  return found.sort((a, b) =>
    b.createdAt.localeCompare(a.createdAt) || sequenceOf(b.name) - sequenceOf(a.name) ||
    b.name.localeCompare(a.name)
  );
}

/**
 * A finished folder never changes, so its size is worked out once. Keyed by
 * name and the folder's own time, so a folder deleted and made again by hand
 * is measured again.
 */
const folderSizes = new Map<string, number>();

async function folderBytes(path: string, name: string): Promise<number> {
  const key = `${name}:${(await Deno.stat(path)).mtime?.getTime()}`;
  let bytes = folderSizes.get(key);
  if (bytes === undefined) {
    bytes = (await folderTar(path, name)).bytes;
    folderSizes.set(key, bytes);
  }
  return bytes;
}

/**
 * What every backup together takes on the disk: each file counted once
 * however many backups link to it.
 */
export async function diskUsage(projectDir: string): Promise<number> {
  // Finished backups never change, so the same set of them takes the same
  // space; walking every attachment of every backup on each refresh would not.
  const backups = await listBackups(projectDir);
  const key = backups.map((backup) => `${backup.name}:${backup.bytes}`).join("/");
  if (usage?.key === key) return usage.bytes;
  const seen = new Set<string>();
  let bytes = 0;
  const walk = async (path: string) => {
    for await (const entry of Deno.readDir(path)) {
      const child = join(path, entry.name);
      if (entry.isDirectory) {
        await walk(child);
      } else if (entry.isFile) {
        const info = await Deno.lstat(child);
        const inode = `${info.dev}:${info.ino}`;
        if (info.ino !== null && seen.has(inode)) continue;
        seen.add(inode);
        bytes += info.size;
      }
    }
  };
  for (const backup of backups) {
    const path = join(projectDir, BACKUPS_DIR, backup.name);
    if (backup.folder) {
      await walk(path);
    } else {
      bytes += backup.bytes;
    }
  }
  usage = { key, bytes };
  return bytes;
}

let usage: { key: string; bytes: number } | null = null;

/** One backup, opened for download, or null when [name] is not one. */
export async function openBackup(
  projectDir: string,
  name: string,
): Promise<
  { stream: ReadableStream<Uint8Array>; bytes: number; fileName: string } | null
> {
  const found = await find(projectDir, name);
  if (!found) return null;
  const path = join(projectDir, BACKUPS_DIR, found.name);
  if (!found.folder) {
    const file = await Deno.open(path);
    return {
      stream: file.readable,
      bytes: (await file.stat()).size,
      fileName: found.name,
    };
  }
  const tar = await folderTar(path, found.name);
  return {
    stream: folderTarStream(tar),
    bytes: tar.bytes,
    fileName: `${found.name}${DOWNLOAD_EXTENSION}`,
  };
}

/** Delete one backup. False when [name] is not one. */
export async function deleteBackup(projectDir: string, name: string): Promise<boolean> {
  const found = await find(projectDir, name);
  if (!found) return false;
  await Deno.remove(join(projectDir, BACKUPS_DIR, found.name), { recursive: true });
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
    await Deno.remove(join(projectDir, BACKUPS_DIR, file.name), { recursive: true });
  }
  return doomed.map((file) => file.name);
}

async function find(projectDir: string, name: string): Promise<BackupFile | undefined> {
  return (await listBackups(projectDir)).find((backup) => backup.name === name);
}
