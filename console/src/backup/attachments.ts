/**
 * The attachments in a backup, each stored once however many backups hold it.
 *
 * Every backup used to carry a whole copy of the attachments, so five daily
 * backups took five times their space — and nearly all of it was the same
 * files, since an upload is never changed once stored. Now a backup keeps one
 * file per distinct content in `backup/attachments/`, named by its SHA-256,
 * and a list (`backup/attachments.txt`) of which object each one is. A file
 * the previous backup already holds is hard-linked from it rather than copied:
 * every backup is still a complete folder, and the disk holds one copy.
 * Deleting an old backup frees only what no other backup links to, with no
 * bookkeeping, because the file system counts the links.
 *
 * Whether an object is unchanged is decided by its path, size and modification
 * time against the previous backup's list, so an unchanged attachment is never
 * read. A new one is hashed as it is copied, and hashed again when it is put
 * back, so a damaged copy is noticed rather than restored.
 *
 * In an encrypted backup each file here is sealed on its own (seal.ts). It is
 * linked only from a backup made with the same passphrase, which is known by
 * that backup's sealed part opening with it.
 */
import { createHash } from "node:crypto";
import { dirname, join } from "jsr:@std/path@1";
import {
  looksSealed,
  type SealKey,
  sealStream,
  type UnsealKeys,
  unsealStream,
} from "./seal.ts";

/** Where storage keeps its files, in its own container and in the console's. */
export const STORAGE_VOLUME = "/var/lib/storage";

/** One stored object: where storage keeps it, and which file in the backup it is. */
export interface AttachmentEntry {
  /** Relative to [STORAGE_VOLUME], with forward slashes. */
  path: string;
  size: number;
  /** Milliseconds, as the volume reported it when the backup was made. */
  mtime: number;
  sha256: string;
}

/** One line per object: hash, size, time, then the path, which may hold spaces. */
export function formatIndex(entries: AttachmentEntry[]): string {
  return entries.map((entry) =>
    `${entry.sha256} ${entry.size} ${entry.mtime} ${entry.path}\n`
  ).join("");
}

/**
 * The list back from its text. Throws on a line that does not parse or a path
 * that would leave the volume: the list decides where restoring writes, and a
 * backup is a file somebody handed the console.
 */
export function parseIndex(text: string): AttachmentEntry[] {
  return text.split("\n").filter((line) => line !== "").map((line) => {
    const match = line.match(/^([0-9a-f]{64}) (\d+) (\d+) (.+)$/);
    if (!match || !isSafePath(match[4])) {
      throw new Error(`The backup's list of attachments is damaged: ${line}`);
    }
    return {
      sha256: match[1],
      size: Number(match[2]),
      mtime: Number(match[3]),
      path: match[4],
    };
  });
}

/** A relative path that stays below the directory it is joined onto. */
export function isSafePath(path: string): boolean {
  if (path.startsWith("/") || path.includes("\\") || path.includes("\0")) return false;
  return path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

/** Every file under [root], as a path relative to it, its size and its time. */
export async function* liveObjects(
  root: string,
  below = "",
): AsyncGenerator<{ path: string; size: number; mtime: number }> {
  const entries: Deno.DirEntry[] = [];
  for await (const entry of Deno.readDir(join(root, below))) entries.push(entry);
  // Sorted, so the list reads the same from one backup to the next.
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const entry of entries) {
    const path = below === "" ? entry.name : `${below}/${entry.name}`;
    if (entry.isDirectory) {
      yield* liveObjects(root, path);
    } else if (entry.isFile) {
      try {
        const info = await Deno.stat(join(root, path));
        yield { path, size: info.size, mtime: info.mtime?.getTime() ?? 0 };
      } catch (error) {
        // Deleted between the listing and the look: it is not in this backup.
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
    }
  }
}

/** The backup to share files with: its attachments folder and its list. */
export interface PreviousAttachments {
  directory: string;
  entries: AttachmentEntry[];
}

/** What collecting the attachments did. */
export interface Collected {
  entries: AttachmentEntry[];
  /** Files new to this backup, and their size on disk. */
  copied: number;
  copiedBytes: number;
  /** Files shared with the previous backup: linked, taking no more space. */
  linked: number;
}

/**
 * Fill [destination] with the attachments under [source], sharing every file
 * [previous] already has, and return the list that says what each one is.
 */
export async function collectAttachments(options: {
  source: string;
  destination: string;
  previous: PreviousAttachments | null;
  seal?: SealKey;
}): Promise<Collected> {
  const { source, destination, previous, seal } = options;
  await Deno.mkdir(destination, { recursive: true, mode: 0o700 });
  const before = new Map(previous?.entries.map((entry) => [entry.path, entry]));
  const result: Collected = { entries: [], copied: 0, copiedBytes: 0, linked: 0 };
  let incoming = 0;

  /** Count what [share] did; false when there was nothing to share. */
  const shared = async (from: string, to: string): Promise<boolean> => {
    const how = await share(from, to);
    if (how === "linked") result.linked++;
    if (how === "copied") {
      result.copied++;
      result.copiedBytes += (await Deno.stat(to)).size;
    }
    return how !== null;
  };

  for await (const object of liveObjects(source)) {
    const known = before.get(object.path);
    if (
      previous && known && known.size === object.size && known.mtime === object.mtime &&
      await shared(
        join(previous.directory, known.sha256),
        join(destination, known.sha256),
      )
    ) {
      result.entries.push({ ...object, sha256: known.sha256 });
      continue;
    }

    const partial = join(destination, `.incoming-${incoming++}`);
    let copied: { sha256: string; size: number };
    try {
      copied = await copyHashed(join(source, object.path), partial, seal);
    } catch (error) {
      await Deno.remove(partial).catch(() => {});
      if (error instanceof Deno.errors.NotFound) continue;
      throw error;
    }
    const target = join(destination, copied.sha256);
    if (await exists(target)) {
      // The same content under a second path: one file serves both.
      await Deno.remove(partial);
    } else if (
      previous && await shared(join(previous.directory, copied.sha256), target)
    ) {
      // Moved or touched, not changed: the previous backup's copy will do.
      await Deno.remove(partial);
    } else {
      await Deno.rename(partial, target);
      result.copied++;
      result.copiedBytes += (await Deno.stat(target)).size;
    }
    result.entries.push({ ...object, size: copied.size, sha256: copied.sha256 });
  }
  return result;
}

/**
 * Put [from] at [to] as a second name for the same file, or as a copy where
 * the file system cannot link — some folders shared into a VM cannot — which
 * still works but saves nothing, and is counted as a copy so the dashboard
 * says so. Null when there is no [from] to share, a previous backup damaged
 * by hand, so the caller copies the live file.
 */
async function share(
  from: string,
  to: string,
): Promise<"linked" | "copied" | "there" | null> {
  if (await exists(to)) return "there";
  try {
    await Deno.link(from, to);
    return "linked";
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return null;
    if (error instanceof Deno.errors.AlreadyExists) return "there";
  }
  try {
    await Deno.copyFile(from, to);
    return "copied";
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return null;
    throw error;
  }
}

/** Copy [from] to [to], sealing it when asked, and hash what was read. */
async function copyHashed(
  from: string,
  to: string,
  seal?: SealKey,
): Promise<{ sha256: string; size: number }> {
  const hash = createHash("sha256");
  let size = 0;
  const input = await Deno.open(from);
  let stream: ReadableStream<Uint8Array> = input.readable.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        hash.update(chunk);
        size += chunk.length;
        controller.enqueue(chunk);
      },
    }),
  );
  if (seal) stream = stream.pipeThrough(sealStream(seal));
  const output = await Deno.open(to, {
    write: true,
    create: true,
    truncate: true,
    mode: 0o600,
  });
  await stream.pipeTo(output.writable);
  return { sha256: hash.digest("hex"), size };
}

/**
 * Decrypt every file in [directory] in place, each through a new file renamed
 * over the old, so a name another backup shares is never written through.
 *
 * Run after the sealed part opened, so the passphrase is known to be right. A
 * file already open is skipped, so a restore stopped halfway can run again;
 * one that will not open is left as it is and named, and putting the
 * attachments back then finds it damaged rather than stopping the restore.
 */
export async function unsealAttachments(
  directory: string,
  passphrase: string,
): Promise<string[]> {
  const keys: UnsealKeys = new Map();
  const names: string[] = [];
  try {
    for await (const entry of Deno.readDir(directory)) {
      if (entry.isFile && /^[0-9a-f]{64}$/.test(entry.name)) names.push(entry.name);
    }
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return [];
    throw error;
  }
  const failed: string[] = [];
  for (const name of names) {
    const file = join(directory, name);
    if (!await isSealedFile(file)) continue;
    const opened = join(directory, `.${name}.open`);
    const output = await Deno.open(opened, {
      write: true,
      create: true,
      truncate: true,
      mode: 0o600,
    });
    try {
      await (await Deno.open(file)).readable
        .pipeThrough(unsealStream(passphrase, keys))
        .pipeTo(output.writable);
      await Deno.rename(opened, file);
    } catch {
      await Deno.remove(opened).catch(() => {});
      failed.push(name);
    }
  }
  return failed;
}

async function isSealedFile(path: string): Promise<boolean> {
  const file = await Deno.open(path);
  try {
    const head = new Uint8Array(16);
    const read = await file.read(head);
    return looksSealed(head.subarray(0, read ?? 0));
  } finally {
    file.close();
  }
}

/** What putting the attachments back found. */
export interface PutBack {
  restored: number;
  /** Paths whose file in the backup no longer matches its hash. Not written. */
  damaged: string[];
  /** Paths whose file the backup does not have at all. */
  missing: string[];
}

/**
 * Write each listed object from [directory] to its place under [target],
 * checking its hash on the way. A damaged or missing file is named and
 * skipped rather than stopping the restore: one lost attachment should not
 * cost the server.
 */
export async function putAttachmentsBack(
  directory: string,
  entries: AttachmentEntry[],
  target: string,
): Promise<PutBack> {
  const result: PutBack = { restored: 0, damaged: [], missing: [] };
  for (const entry of entries) {
    const source = join(directory, entry.sha256);
    if (!await exists(source)) {
      result.missing.push(entry.path);
      continue;
    }
    const destination = join(target, entry.path);
    await Deno.mkdir(dirname(destination), { recursive: true });
    const partial = `${destination}.restoring`;
    const copied = await copyHashed(source, partial);
    if (copied.sha256 !== entry.sha256) {
      await Deno.remove(partial);
      result.damaged.push(entry.path);
      continue;
    }
    await Deno.chmod(partial, 0o644);
    await Deno.rename(partial, destination);
    if (entry.mtime > 0) {
      await Deno.utime(destination, new Date(), new Date(entry.mtime));
    }
    result.restored++;
  }
  return result;
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.lstat(path);
    return true;
  } catch {
    return false;
  }
}
