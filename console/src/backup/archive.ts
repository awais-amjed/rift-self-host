/**
 * A backup: a folder that is a server waiting to be run.
 *
 * It holds the compose file, the instructions, and either the payload in the
 * clear — `.env` and `backup/` — or, with a passphrase, one sealed file holding
 * `.env`, the database and the list of attachments, with each attachment
 * sealed on its own beside it (attachments.ts says why). `docker compose up -d`
 * in that folder is the whole restore: the console finds the payload beside it
 * and does the rest, asking for the passphrase first if there is one.
 *
 * On the server the backup stays a folder, so the next one can share its
 * attachments. A download is the same folder as one `.tar`, written as it is
 * sent; tar is on every server this runs on and on Windows 10 and 11, and the
 * size of the file is known before the first byte, so a browser can show how
 * far along it is. Nothing in it compresses: the dump is already gzipped and
 * attachments are encrypted.
 *
 * Backups from before (format 1) are single `.tar.gz` files with the
 * attachments as a tar inside. They are still listed, downloaded and restored.
 */
import { TarStream, type TarStreamInput, UntarStream } from "jsr:@std/tar@0.1";
import { dirname, join } from "jsr:@std/path@1";
import { type SealKey, type SealOptions, sealStream, unsealStream } from "./seal.ts";

/** A format-1 backup, one compressed file. */
export const ARCHIVE_EXTENSION = ".tar.gz";
/** What downloading a backup folder gives. */
export const DOWNLOAD_EXTENSION = ".tar";
export const SEALED_FILE = "backup.sealed";
export const PAYLOAD_DIR = "backup";
export const MANIFEST = `${PAYLOAD_DIR}/manifest.json`;
export const DATABASE_DUMP = `${PAYLOAD_DIR}/database.sql.gz`;
export const ATTACHMENT_INDEX = `${PAYLOAD_DIR}/attachments.txt`;
export const ATTACHMENT_DIR = `${PAYLOAD_DIR}/attachments`;
/** Format 1's attachments, a tar of the whole volume. */
export const STORAGE_ARCHIVE = `${PAYLOAD_DIR}/storage.tar.gz`;

/** What a sealed backup holds, in the order it holds them: the list comes early,
 * so the next backup can read it without decrypting the database. */
export const SEALED_PATHS = [MANIFEST, ATTACHMENT_INDEX, ".env", DATABASE_DUMP] as const;

/** Everything a sealed backup of either format may contain, and so everything opening one may write. */
export const PAYLOAD_PATHS = [
  ".env",
  MANIFEST,
  ATTACHMENT_INDEX,
  DATABASE_DUMP,
  STORAGE_ARCHIVE,
] as const;
export type PayloadPath = (typeof PAYLOAD_PATHS)[number];

/** What a backup says about itself. No secrets: it is readable in either kind. */
export interface Manifest {
  /** 1: attachments as one tar inside. 2: one file each, shared between backups. */
  format: 1 | 2;
  createdAt: string;
  consoleVersion: string;
  domain: string;
  encrypted: boolean;
}

/**
 * `rift-backup-2026-09-15-1203`, in UTC, with `-2`, `-3`… for a second backup
 * in the same minute and `-encrypted` when sealed.
 *
 * The number goes before the suffix, so "is it encrypted" stays a question the
 * name answers without opening the file.
 */
export function backupName(at: Date, encrypted: boolean, sequence = 1): string {
  const stamp = at.toISOString().slice(0, 16).replace("T", "-").replace(":", "");
  return `rift-backup-${stamp}${sequence > 1 ? `-${sequence}` : ""}${
    encrypted ? "-encrypted" : ""
  }`;
}

/** Whether [path] is one a sealed backup is allowed to write. Nothing else is. */
export function isPayloadPath(path: string): path is PayloadPath {
  return (PAYLOAD_PATHS as readonly string[]).includes(path);
}

/** The instructions that travel with the backup. */
export function restoreInstructions(manifest: Manifest, name: string): string {
  const domain = manifest.domain || "the same address this server had";
  const lines = [
    "Restoring this Rift server",
    "==========================",
    "",
    `1. Point ${domain} at the machine you are restoring onto. It has to be`,
    "   the same one: every member's identity on this server is derived from it.",
    "",
    "2. Open this folder in a terminal. From a downloaded file, extract it",
    "   first, which makes the folder:",
    "",
    `     tar xf ${name}${DOWNLOAD_EXTENSION}`,
    `     cd ${name}`,
    "",
    "3. Start it:",
    "",
    "     docker compose up -d",
    "",
  ];
  if (manifest.encrypted) {
    lines.push(
      "4. Open the console at http://localhost:8080 — over an SSH tunnel on a",
      "   remote machine — and enter the passphrase this backup was made with.",
      "   It restores everything from there.",
    );
  } else {
    lines.push(
      "   That is all. The console loads the database and the attachments and",
      "   restarts the stack. Watch it with: docker compose logs -f console",
    );
  }
  lines.push(
    "",
    `Made ${manifest.createdAt} by Rift console ${manifest.consoleVersion}.`,
    "",
  );
  return lines.join("\n");
}

/**
 * Seal [files] — payload paths and the files on disk holding them, in
 * [SEALED_PATHS] order — into [destination].
 */
export async function sealPayload(
  files: Partial<Record<PayloadPath, string>>,
  destination: string,
  secret: string | SealKey,
  options?: SealOptions,
): Promise<void> {
  const entries = async function* (): AsyncGenerator<TarStreamInput> {
    for (const path of SEALED_PATHS) {
      const file = files[path];
      if (file === undefined) continue;
      yield {
        type: "file",
        path,
        size: (await Deno.stat(file)).size,
        readable: (await Deno.open(file)).readable,
        options: { mode: 0o600 },
      };
    }
  };
  const out = await Deno.open(destination, {
    write: true,
    create: true,
    truncate: true,
    mode: 0o600,
  });
  await ReadableStream.from(entries())
    .pipeThrough(new TarStream())
    .pipeThrough(sealStream(secret, options))
    .pipeTo(out.writable);
}

/**
 * The list of attachments inside a sealed backup, or null when [passphrase]
 * does not open it. Reading stops at the list, so the database — the bulk of
 * the file — is never decrypted for it.
 */
export async function readSealedIndex(
  sealedFile: string,
  passphrase: string,
): Promise<string | null> {
  const entries = (await Deno.open(sealedFile)).readable
    .pipeThrough(unsealStream(passphrase))
    .pipeThrough(new UntarStream());
  try {
    for await (const entry of entries) {
      if (entry.path === ATTACHMENT_INDEX && entry.readable) {
        return await new Response(entry.readable).text();
      }
      await entry.readable?.cancel();
    }
    return null;
  } catch {
    return null;
  } finally {
    await entries.cancel().catch(() => {});
  }
}

/** One entry of a folder written as a tar, with what it takes to write it. */
interface FolderEntry {
  path: string;
  /** The file on disk, or none for a directory. */
  file?: string;
  size: number;
  mode: number;
}

/** A backup folder as one tar: what it holds, and the exact size it will be. */
export interface FolderTar {
  entries: FolderEntry[];
  bytes: number;
}

/**
 * Everything under [folder], named below [name], in the order a tar of it is
 * written. The size counts what TarStream writes: a 512-byte header for each
 * entry, each file padded to a whole block, and two empty blocks to finish.
 */
export async function folderTar(folder: string, name: string): Promise<FolderTar> {
  const entries: FolderEntry[] = [];
  const walk = async (directory: string, below: string) => {
    const children: Deno.DirEntry[] = [];
    for await (const child of Deno.readDir(directory)) children.push(child);
    children.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const child of children) {
      const path = `${below}/${child.name}`;
      const file = join(directory, child.name);
      const info = await Deno.stat(file);
      const mode = (info.mode ?? 0o600) & 0o777;
      if (child.isDirectory) {
        entries.push({ path, size: 0, mode });
        await walk(file, path);
      } else if (child.isFile) {
        entries.push({ path, file, size: info.size, mode });
      }
    }
  };
  entries.push({ path: name, size: 0, mode: 0o755 });
  await walk(folder, name);
  const bytes = entries.reduce(
    (sum, entry) => sum + 512 + Math.ceil(entry.size / 512) * 512,
    1024,
  );
  return { entries, bytes };
}

/** The tar [folderTar] described, written as it is read. */
export function folderTarStream(tar: FolderTar): ReadableStream<Uint8Array> {
  const inputs = async function* (): AsyncGenerator<TarStreamInput> {
    for (const entry of tar.entries) {
      if (entry.file === undefined) {
        yield { type: "directory", path: entry.path, options: { mode: entry.mode } };
      } else {
        yield {
          type: "file",
          path: entry.path,
          size: entry.size,
          readable: (await Deno.open(entry.file)).readable,
          options: { mode: entry.mode },
        };
      }
    }
  };
  return ReadableStream.from(inputs()).pipeThrough(new TarStream());
}

/**
 * Open [sealedFile] with [passphrase] and write its payload into [directory].
 *
 * Only the four payload paths are written: an archive naming anything else —
 * `../.ssh/authorized_keys`, say — is refused before a byte of it lands. A
 * wrong passphrase fails on the first frame, before anything is written.
 */
export async function unsealInto(
  sealedFile: string,
  passphrase: string,
  directory: string,
): Promise<PayloadPath[]> {
  const written: PayloadPath[] = [];
  const entries = (await Deno.open(sealedFile)).readable
    .pipeThrough(unsealStream(passphrase))
    .pipeThrough(new UntarStream());

  for await (const entry of entries) {
    const path = entry.path.replace(/^\.\//, "");
    if (!isPayloadPath(path)) {
      await entry.readable?.cancel();
      throw new Error(`This backup contains a file it should not: ${path}`);
    }
    if (!entry.readable) continue;
    const target = join(directory, path);
    await Deno.mkdir(dirname(target), { recursive: true });
    const file = await Deno.open(target, {
      write: true,
      create: true,
      truncate: true,
      mode: 0o600,
    });
    await entry.readable.pipeTo(file.writable);
    written.push(path);
  }
  return written;
}
