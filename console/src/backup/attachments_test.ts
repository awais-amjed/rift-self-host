import { assert, assertEquals, assertNotEquals, assertThrows } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import {
  type AttachmentEntry,
  collectAttachments,
  formatIndex,
  isSafePath,
  parseIndex,
  putAttachmentsBack,
  unsealAttachments,
} from "./attachments.ts";
import { deriveSealKey } from "./seal.ts";

const FAST = { iterations: 1000, chunkBytes: 64 };

/** A storage volume holding these files. */
async function volume(files: Record<string, string>): Promise<string> {
  const root = await Deno.makeTempDir({ prefix: "rift-volume-" });
  for (const [path, body] of Object.entries(files)) {
    await Deno.mkdir(join(root, path, ".."), { recursive: true });
    await Deno.writeTextFile(join(root, path), body);
  }
  return root;
}

async function inode(path: string): Promise<number | null> {
  return (await Deno.stat(path)).ino;
}

Deno.test("a second backup shares unchanged attachments and copies only the new", async () => {
  const live = await volume({
    "stub/stub/avatars/me": "avatar",
    "stub/stub/chat-1/a.bin/v1": "first upload",
    "stub/stub/chat-1/b.bin/v1": "first upload",
  });
  const backups = await Deno.makeTempDir();
  try {
    const first = await collectAttachments({
      source: live,
      destination: join(backups, "one"),
      previous: null,
    });
    // Two objects with the same content are one file.
    assertEquals(first.copied, 2);
    assertEquals(first.entries.length, 3);
    assertEquals(first.entries[1].sha256, first.entries[2].sha256);

    await Deno.mkdir(join(live, "stub/stub/chat-1/c.bin"));
    await Deno.writeTextFile(join(live, "stub/stub/chat-1/c.bin/v1"), "later upload");
    const second = await collectAttachments({
      source: live,
      destination: join(backups, "two"),
      previous: { directory: join(backups, "one"), entries: first.entries },
    });
    assertEquals(second.copied, 1);
    assertEquals(second.copiedBytes, "later upload".length);
    // Files, not objects: the two with the same content are one file.
    assertEquals(second.linked, 2);

    // The same file on disk, not a copy of it.
    const shared = first.entries[0].sha256;
    assertEquals(
      await inode(join(backups, "two", shared)),
      await inode(join(backups, "one", shared)),
    );
    // Each backup is whole on its own: deleting the first loses nothing.
    await Deno.remove(join(backups, "one"), { recursive: true });
    const restored = await Deno.makeTempDir();
    const put = await putAttachmentsBack(join(backups, "two"), second.entries, restored);
    assertEquals(put, { restored: 4, damaged: [], missing: [] });
    assertEquals(
      await Deno.readTextFile(join(restored, "stub/stub/chat-1/c.bin/v1")),
      "later upload",
    );
    await Deno.remove(restored, { recursive: true });
  } finally {
    await Deno.remove(live, { recursive: true });
    await Deno.remove(backups, { recursive: true });
  }
});

Deno.test("a changed file is copied again, never trusted to its old hash", async () => {
  const live = await volume({ "stub/stub/avatars/me": "old face" });
  const backups = await Deno.makeTempDir();
  try {
    const first = await collectAttachments({
      source: live,
      destination: join(backups, "one"),
      previous: null,
    });
    await Deno.writeTextFile(join(live, "stub/stub/avatars/me"), "new face!");
    const second = await collectAttachments({
      source: live,
      destination: join(backups, "two"),
      previous: { directory: join(backups, "one"), entries: first.entries },
    });
    assertEquals(second.copied, 1);
    assertNotEquals(second.entries[0].sha256, first.entries[0].sha256);
  } finally {
    await Deno.remove(live, { recursive: true });
    await Deno.remove(backups, { recursive: true });
  }
});

Deno.test("encrypted attachments are sealed, shared, and open with the passphrase", async () => {
  const live = await volume({ "stub/stub/chat-1/a.bin/v1": "secret bytes ".repeat(20) });
  const backups = await Deno.makeTempDir();
  try {
    const first = await collectAttachments({
      source: live,
      destination: join(backups, "one"),
      previous: null,
      seal: await deriveSealKey("correct horse", FAST),
    });
    const file = join(backups, "one", first.entries[0].sha256);
    assert(!(await Deno.readTextFile(file)).includes("secret"), "stored in the clear");

    // A second backup under a new derivation of the same passphrase shares it.
    const second = await collectAttachments({
      source: live,
      destination: join(backups, "two"),
      previous: { directory: join(backups, "one"), entries: first.entries },
      seal: await deriveSealKey("correct horse", FAST),
    });
    assertEquals(second.linked, 1);

    // Opening decrypts in place without touching the other backup's copy, and
    // opening again — a restore stopped halfway — finds nothing left to do.
    assertEquals(await unsealAttachments(join(backups, "two"), "correct horse"), []);
    assertEquals(await unsealAttachments(join(backups, "two"), "correct horse"), []);
    assert(
      !(await Deno.readTextFile(file)).includes("secret"),
      "the shared copy changed",
    );
    const restored = await Deno.makeTempDir();
    const put = await putAttachmentsBack(join(backups, "two"), second.entries, restored);
    assertEquals(put.restored, 1);
    await Deno.remove(restored, { recursive: true });
  } finally {
    await Deno.remove(live, { recursive: true });
    await Deno.remove(backups, { recursive: true });
  }
});

Deno.test("an encrypted attachment that will not open is named, not fatal", async () => {
  const live = await volume({
    "stub/stub/chat-1/a.bin/v1": "first",
    "stub/stub/chat-1/b.bin/v1": "second",
  });
  const backups = await Deno.makeTempDir();
  try {
    const { entries } = await collectAttachments({
      source: live,
      destination: backups,
      previous: null,
      seal: await deriveSealKey("correct horse", FAST),
    });
    const damaged = join(backups, entries[1].sha256);
    const bytes = await Deno.readFile(damaged);
    bytes[bytes.length - 1] ^= 1;
    await Deno.writeFile(damaged, bytes);

    assertEquals(await unsealAttachments(backups, "correct horse"), [entries[1].sha256]);
    const restored = await Deno.makeTempDir();
    const put = await putAttachmentsBack(backups, entries, restored);
    assertEquals(put.damaged, ["stub/stub/chat-1/b.bin/v1"]);
    assertEquals(put.restored, 1);
    await Deno.remove(restored, { recursive: true });
  } finally {
    await Deno.remove(live, { recursive: true });
    await Deno.remove(backups, { recursive: true });
  }
});

Deno.test("a damaged or missing attachment is left out and named", async () => {
  const live = await volume({
    "stub/stub/chat-1/a.bin/v1": "kept",
    "stub/stub/chat-1/b.bin/v1": "damaged",
    "stub/stub/chat-1/c.bin/v1": "missing",
  });
  const backups = await Deno.makeTempDir();
  const restored = await Deno.makeTempDir();
  try {
    const { entries } = await collectAttachments({
      source: live,
      destination: backups,
      previous: null,
    });
    await Deno.writeTextFile(join(backups, entries[1].sha256), "dAmaged");
    await Deno.remove(join(backups, entries[2].sha256));

    const put = await putAttachmentsBack(backups, entries, restored);
    assertEquals(put, {
      restored: 1,
      damaged: ["stub/stub/chat-1/b.bin/v1"],
      missing: ["stub/stub/chat-1/c.bin/v1"],
    });
    await assertMissing(join(restored, "stub/stub/chat-1/b.bin/v1"));
  } finally {
    for (const dir of [live, backups, restored]) {
      await Deno.remove(dir, { recursive: true });
    }
  }
});

async function assertMissing(path: string) {
  try {
    await Deno.stat(path);
  } catch (error) {
    assert(error instanceof Deno.errors.NotFound);
    return;
  }
  throw new Error(`${path} was written`);
}

Deno.test("the list survives a round trip and refuses paths that leave the volume", () => {
  const entries: AttachmentEntry[] = [
    {
      path: "stub/stub/chat-1/with space.bin/v1",
      size: 12,
      mtime: 1700,
      sha256: "a".repeat(64),
    },
  ];
  assertEquals(parseIndex(formatIndex(entries)), entries);

  for (
    const path of ["../etc/passwd", "/etc/passwd", "a/../../b", "a//b", "./a", "a\\b"]
  ) {
    assert(!isSafePath(path), path);
    assertThrows(() => parseIndex(`${"a".repeat(64)} 1 1 ${path}\n`));
  }
  assert(isSafePath("stub/stub/avatars/me"));
});
