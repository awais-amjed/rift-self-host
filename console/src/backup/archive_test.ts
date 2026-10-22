import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { TarStream, UntarStream } from "jsr:@std/tar@0.1";
import { join } from "jsr:@std/path@1";
import {
  ATTACHMENT_INDEX,
  backupName,
  DATABASE_DUMP,
  folderTar,
  folderTarStream,
  isPayloadPath,
  MANIFEST,
  type Manifest,
  PAYLOAD_PATHS,
  readSealedIndex,
  restoreInstructions,
  SEALED_PATHS,
  sealPayload,
  STORAGE_ARCHIVE,
  unsealInto,
} from "./archive.ts";
import { sealStream } from "./seal.ts";

const FAST = { iterations: 1000, chunkBytes: 256 };

const manifest = (encrypted: boolean): Manifest => ({
  format: 2,
  createdAt: "2026-09-15T12:03:00.000Z",
  consoleVersion: "0.2.0",
  domain: "chat.example.com",
  encrypted,
});

/** A payload of recognisable contents, each in a file of its own. */
async function payload(): Promise<{ dir: string; files: Record<string, string> }> {
  const dir = await Deno.makeTempDir({ prefix: "rift-backup-" });
  const files: Record<string, string> = {};
  for (
    const [path, body] of [
      [".env", "JWT_SECRET=abc\n"],
      [MANIFEST, JSON.stringify(manifest(true))],
      [ATTACHMENT_INDEX, `${"a".repeat(64)} 3 1 stub/stub/avatars/me\n`],
      [DATABASE_DUMP, "x".repeat(1500)],
      [STORAGE_ARCHIVE, "y".repeat(700)],
    ]
  ) {
    const file = join(dir, "source", path);
    await Deno.mkdir(join(file, ".."), { recursive: true });
    await Deno.writeTextFile(file, body);
    files[path] = file;
  }
  return { dir, files };
}

Deno.test("a sealed payload opens to what went in, and its list reads alone", async () => {
  const { dir, files } = await payload();
  const sealed = join(dir, "backup.sealed");
  await sealPayload(files, sealed, "correct horse", FAST);
  assert(!(await Deno.readTextFile(sealed)).includes("JWT_SECRET"), "secrets visible");

  assertEquals(
    await readSealedIndex(sealed, "correct horse"),
    await Deno.readTextFile(files[ATTACHMENT_INDEX]),
  );
  assertEquals(await readSealedIndex(sealed, "wrong"), null);

  const restored = join(dir, "restored");
  const written = await unsealInto(sealed, "correct horse", restored);
  // Only the four a new backup seals: format 1's tar of attachments is not one.
  assertEquals(written, [...SEALED_PATHS]);
  for (const path of SEALED_PATHS) {
    assertEquals(
      await Deno.readTextFile(join(restored, path)),
      await Deno.readTextFile(files[path]),
    );
  }
  await assertRejects(() => unsealInto(sealed, "wrong", join(dir, "nope")), Error);
  await Deno.remove(dir, { recursive: true });
});

Deno.test("a sealed backup from before folders still opens", async () => {
  const { dir, files } = await payload();
  const sealed = join(dir, "backup.sealed");
  const format1 = [".env", MANIFEST, DATABASE_DUMP, STORAGE_ARCHIVE];
  const entries = async function* () {
    for (const path of format1) {
      yield {
        type: "file" as const,
        path,
        size: (await Deno.stat(files[path])).size,
        readable: (await Deno.open(files[path])).readable,
      };
    }
  };
  await ReadableStream.from(entries())
    .pipeThrough(new TarStream())
    .pipeThrough(sealStream("correct horse", FAST))
    .pipeTo((await Deno.create(sealed)).writable);

  const restored = join(dir, "restored");
  assertEquals(await unsealInto(sealed, "correct horse", restored), format1);
  assertEquals(
    await Deno.readTextFile(join(restored, STORAGE_ARCHIVE)),
    "y".repeat(700),
  );
  await Deno.remove(dir, { recursive: true });
});

Deno.test("a folder downloads as a tar of exactly the size promised", async () => {
  const dir = await Deno.makeTempDir();
  const folder = join(dir, "rift-backup-2026-09-15-1203");
  await Deno.mkdir(join(folder, "backup", "attachments"), { recursive: true });
  // Sizes either side of a tar block, and none at all.
  const files: Record<string, number> = {
    "docker-compose.yml": 0,
    "RESTORE.txt": 1,
    ".env": 511,
    "backup/database.sql.gz": 512,
    [`backup/attachments/${"b".repeat(64)}`]: 513,
    [`backup/attachments/${"c".repeat(64)}`]: 4000,
  };
  for (const [path, size] of Object.entries(files)) {
    await Deno.writeFile(join(folder, path), new Uint8Array(size).fill(7));
  }

  const tar = await folderTar(folder, "rift-backup-2026-09-15-1203");
  const bytes = new Uint8Array(await new Response(folderTarStream(tar)).arrayBuffer());
  assertEquals(bytes.length, tar.bytes);

  const found = new Map<string, number>();
  for await (const entry of ReadableStream.from([bytes]).pipeThrough(new UntarStream())) {
    found.set(
      entry.path,
      entry.readable ? (await new Response(entry.readable).arrayBuffer()).byteLength : -1,
    );
  }
  for (const [path, size] of Object.entries(files)) {
    assertEquals(found.get(`rift-backup-2026-09-15-1203/${path}`), size, path);
  }
  await Deno.remove(dir, { recursive: true });
});

Deno.test("opening a backup writes nothing outside its own names", () => {
  for (const path of PAYLOAD_PATHS) assert(isPayloadPath(path));
  for (
    const path of [
      "../.env",
      "backup/../../etc/passwd",
      "/etc/passwd",
      "backup/other",
      "x",
    ]
  ) {
    assert(!isPayloadPath(path), path);
  }
});

Deno.test("the name says when it was made, in UTC, and whether it is encrypted", () => {
  const at = new Date("2026-09-15T12:03:45Z");
  assertEquals(backupName(at, false), "rift-backup-2026-09-15-1203");
  assertEquals(backupName(at, true), "rift-backup-2026-09-15-1203-encrypted");
  // A second in the same minute must not overwrite the first, and must still
  // read as encrypted from its name.
  assertEquals(backupName(at, false, 2), "rift-backup-2026-09-15-1203-2");
  assertEquals(backupName(at, true, 3), "rift-backup-2026-09-15-1203-3-encrypted");
});

Deno.test("the instructions name the domain, and ask for a passphrase only when there is one", () => {
  const plain = restoreInstructions(manifest(false), "rift-backup-x");
  assertStringIncludes(plain, "chat.example.com");
  assertStringIncludes(plain, "tar xf rift-backup-x.tar");
  assertStringIncludes(plain, "docker compose up -d");
  assert(!plain.includes("passphrase"));

  assertStringIncludes(
    restoreInstructions(manifest(true), "rift-backup-x"),
    "passphrase",
  );
});
