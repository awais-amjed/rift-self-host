/**
 * The backup file: one `.tar.gz` that is a server folder waiting to be run.
 *
 * Extracting it gives a folder with the compose file, the instructions, and
 * either the payload in the clear — `.env` and `backup/` — or, with a
 * passphrase, one sealed file holding the same. `docker compose up -d` in that
 * folder is the whole restore: the console finds the payload beside it and
 * does the rest, asking for the passphrase first if there is one.
 *
 * `.tar.gz` rather than `.zip` because tar is on every server this runs on and
 * on Windows 10 and 11; the attachments inside are a tar of their own.
 */
import { TarStream, type TarStreamInput, UntarStream } from "jsr:@std/tar@0.1";
import { dirname, join } from "jsr:@std/path@1";
import { type SealOptions, sealStream, unsealStream } from "./seal.ts";

export const ARCHIVE_EXTENSION = ".tar.gz";
export const SEALED_FILE = "backup.sealed";
export const PAYLOAD_DIR = "backup";
export const MANIFEST = `${PAYLOAD_DIR}/manifest.json`;
export const DATABASE_DUMP = `${PAYLOAD_DIR}/database.sql.gz`;
export const STORAGE_ARCHIVE = `${PAYLOAD_DIR}/storage.tar.gz`;

/** Everything a sealed backup may contain, and so everything opening one may write. */
export const PAYLOAD_PATHS = [".env", MANIFEST, DATABASE_DUMP, STORAGE_ARCHIVE] as const;
export type PayloadPath = (typeof PAYLOAD_PATHS)[number];

/** What a backup says about itself. No secrets: it is readable in either kind. */
export interface Manifest {
  format: 1;
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
    "2. Extract this file and open the folder it makes:",
    "",
    `     tar xzf ${name}${ARCHIVE_EXTENSION}`,
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

function textEntry(path: string, text: string, mode: number): TarStreamInput {
  const bytes = new TextEncoder().encode(text);
  return {
    type: "file",
    path,
    size: bytes.length,
    readable: ReadableStream.from([bytes]),
    options: { mode },
  };
}

async function fileEntry(
  path: string,
  file: string,
  mode: number,
): Promise<TarStreamInput> {
  return {
    type: "file",
    path,
    size: (await Deno.stat(file)).size,
    readable: (await Deno.open(file)).readable,
    options: { mode },
  };
}

/** What [writeArchive] needs. */
export interface ArchiveSource {
  /** Where to write. */
  destination: string;
  /** The folder extraction makes, and the name the file shares. */
  name: string;
  composeFile: string;
  instructions: string;
  /** Each payload path and the file on disk holding it. */
  payload: Record<PayloadPath, string>;
  /** Seal the payload with this, or leave it in the clear when absent. */
  passphrase?: string;
  /** Somewhere to put the sealed payload while the archive is written. */
  workDir: string;
  seal?: SealOptions;
}

/** Write the backup file. */
export async function writeArchive(source: ArchiveSource): Promise<void> {
  const { name, payload } = source;

  let sealed: string | null = null;
  if (source.passphrase) {
    sealed = join(source.workDir, SEALED_FILE);
    const inner = async function* (): AsyncGenerator<TarStreamInput> {
      for (const path of PAYLOAD_PATHS) yield await fileEntry(path, payload[path], 0o600);
    };
    const out = await Deno.open(sealed, { write: true, create: true, truncate: true });
    await ReadableStream.from(inner())
      .pipeThrough(new TarStream())
      .pipeThrough(sealStream(source.passphrase, source.seal))
      .pipeTo(out.writable);
  }

  const outer = async function* (): AsyncGenerator<TarStreamInput> {
    yield { type: "directory", path: name, options: { mode: 0o755 } };
    yield await fileEntry(`${name}/docker-compose.yml`, source.composeFile, 0o644);
    yield textEntry(`${name}/RESTORE.txt`, source.instructions, 0o644);
    if (sealed !== null) {
      yield await fileEntry(`${name}/${SEALED_FILE}`, sealed, 0o600);
      return;
    }
    yield { type: "directory", path: `${name}/${PAYLOAD_DIR}`, options: { mode: 0o700 } };
    for (const path of PAYLOAD_PATHS) {
      yield await fileEntry(`${name}/${path}`, payload[path], 0o600);
    }
  };

  const out = await Deno.open(source.destination, {
    write: true,
    create: true,
    truncate: true,
    mode: 0o600,
  });
  await ReadableStream.from(outer())
    .pipeThrough(new TarStream())
    .pipeThrough(new CompressionStream("gzip"))
    .pipeTo(out.writable);
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
