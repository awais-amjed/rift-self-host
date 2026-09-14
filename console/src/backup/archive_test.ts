import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { UntarStream } from "jsr:@std/tar@0.1";
import { join } from "jsr:@std/path@1";
import {
  backupName,
  DATABASE_DUMP,
  isPayloadPath,
  MANIFEST,
  type Manifest,
  PAYLOAD_PATHS,
  restoreInstructions,
  SEALED_FILE,
  STORAGE_ARCHIVE,
  unsealInto,
  writeArchive,
} from "./archive.ts";

const FAST = { iterations: 1000, chunkBytes: 256 };

const manifest = (encrypted: boolean): Manifest => ({
  format: 1,
  createdAt: "2026-09-15T12:03:00.000Z",
  consoleVersion: "0.2.0",
  domain: "chat.example.com",
  encrypted,
});

/** A project with a compose file and a payload of recognisable contents. */
async function project(): Promise<{ dir: string; payload: Record<string, string> }> {
  const dir = await Deno.makeTempDir({ prefix: "rift-backup-" });
  await Deno.writeTextFile(join(dir, "docker-compose.yml"), "name: rift\n");
  const payload: Record<string, string> = {};
  for (
    const [path, body] of [
      [".env", "JWT_SECRET=abc\n"],
      [MANIFEST, JSON.stringify(manifest(false))],
      [DATABASE_DUMP, "x".repeat(1500)],
      [STORAGE_ARCHIVE, "y".repeat(700)],
    ]
  ) {
    const file = join(dir, "source", path);
    await Deno.mkdir(join(file, ".."), { recursive: true });
    await Deno.writeTextFile(file, body);
    payload[path] = file;
  }
  return { dir, payload };
}

async function entriesOf(file: string): Promise<Map<string, string | null>> {
  const found = new Map<string, string | null>();
  const stream = (await Deno.open(file)).readable
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new UntarStream());
  for await (const entry of stream) {
    found.set(
      entry.path,
      entry.readable ? await new Response(entry.readable).text() : null,
    );
  }
  return found;
}

Deno.test("a plain backup extracts to a folder ready to run", async () => {
  const { dir, payload } = await project();
  const destination = join(dir, "out.tar.gz");
  await writeArchive({
    destination,
    name: "rift-backup-2026-09-15-1203",
    composeFile: join(dir, "docker-compose.yml"),
    instructions: "read me",
    payload: payload as never,
    workDir: dir,
  });

  const entries = await entriesOf(destination);
  const root = "rift-backup-2026-09-15-1203/";
  assertEquals(entries.get(`${root}docker-compose.yml`), "name: rift\n");
  assertEquals(entries.get(`${root}RESTORE.txt`), "read me");
  for (const path of PAYLOAD_PATHS) {
    assertEquals(
      entries.get(`${root}${path}`),
      await Deno.readTextFile(payload[path]),
      path,
    );
  }
  assertEquals(entries.has(`${root}${SEALED_FILE}`), false);
  await Deno.remove(dir, { recursive: true });
});

Deno.test("an encrypted backup shows only the compose file and the instructions", async () => {
  const { dir, payload } = await project();
  const destination = join(dir, "out.tar.gz");
  await writeArchive({
    destination,
    name: "b",
    composeFile: join(dir, "docker-compose.yml"),
    instructions: "read me",
    payload: payload as never,
    passphrase: "correct horse",
    workDir: dir,
    seal: FAST,
  });

  const entries = await entriesOf(destination);
  assertEquals(
    [...entries.keys()].filter((path) => entries.get(path) !== null).sort(),
    ["b/RESTORE.txt", `b/${SEALED_FILE}`, "b/docker-compose.yml"],
  );
  // Nothing of the payload readable in the archive itself.
  for (const body of entries.values()) {
    assert(!body?.includes("JWT_SECRET"), "the secrets are visible");
  }

  // And opening it puts the payload back exactly.
  const extracted = await Deno.makeTempDir();
  const sealed = join(extracted, SEALED_FILE);
  await Deno.writeTextFile(sealed, "");
  const bytes = (await Deno.open(destination)).readable
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new UntarStream());
  for await (const entry of bytes) {
    if (entry.path === `b/${SEALED_FILE}`) {
      await entry.readable!.pipeTo((await Deno.create(sealed)).writable);
    } else {
      await entry.readable?.cancel();
    }
  }
  const restored = join(extracted, "restored");
  const written = await unsealInto(sealed, "correct horse", restored);
  assertEquals(written.sort(), [...PAYLOAD_PATHS].sort());
  for (const path of PAYLOAD_PATHS) {
    assertEquals(
      await Deno.readTextFile(join(restored, path)),
      await Deno.readTextFile(payload[path]),
    );
  }

  await assertRejects(() => unsealInto(sealed, "wrong", join(extracted, "nope")), Error);
  await Deno.remove(dir, { recursive: true });
  await Deno.remove(extracted, { recursive: true });
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
  assertStringIncludes(plain, "tar xzf rift-backup-x.tar.gz");
  assertStringIncludes(plain, "docker compose up -d");
  assert(!plain.includes("passphrase"));

  assertStringIncludes(
    restoreInstructions(manifest(true), "rift-backup-x"),
    "passphrase",
  );
});
