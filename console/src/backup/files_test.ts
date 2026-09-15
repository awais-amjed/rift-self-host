import { assert, assertEquals } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import {
  BACKUPS_DIR,
  deleteBackup,
  listBackups,
  openBackup,
  pruneBackups,
  startedAt,
} from "./files.ts";

/** A project directory with these backups in it, and an `.env` beside them. */
async function project(names: string[]): Promise<string> {
  const projectDir = await Deno.makeTempDir();
  await Deno.mkdir(join(projectDir, BACKUPS_DIR));
  await Deno.writeTextFile(join(projectDir, ".env"), "SECRET=1");
  await Deno.writeTextFile(join(projectDir, BACKUPS_DIR, "notes.tar.gz"), "x");
  for (const name of names) {
    await Deno.writeTextFile(join(projectDir, BACKUPS_DIR, name), "backup");
  }
  return projectDir;
}

/** Names from query strings that must never reach a file. */
const REFUSED = ["../.env", ".env", "notes.tar.gz", `../${BACKUPS_DIR}/x`, ""];

Deno.test("a download serves only files the backup list shows", async () => {
  // The name comes straight from the query string. Anything that is not a
  // listed backup — above all a path climbing out to `.env` — must be refused.
  const name = "rift-backup-2026-09-15-1203.tar.gz";
  const projectDir = await project([name]);
  try {
    const opened = await openBackup(projectDir, name);
    assert(opened, "a listed backup was refused");
    assertEquals(opened.bytes, 6);
    assertEquals(await new Response(opened.file.readable).text(), "backup");

    for (const refused of [...REFUSED, `../${BACKUPS_DIR}/${name}`]) {
      assertEquals(await openBackup(projectDir, refused), null, `served ${refused}`);
    }
  } finally {
    await Deno.remove(projectDir, { recursive: true });
  }
});

Deno.test("deleting refuses anything that is not a listed backup", async () => {
  const name = "rift-backup-2026-09-15-1203.tar.gz";
  const projectDir = await project([name]);
  try {
    for (const refused of REFUSED) {
      assertEquals(await deleteBackup(projectDir, refused), false, `deleted ${refused}`);
    }
    assertEquals(await Deno.readTextFile(join(projectDir, ".env")), "SECRET=1");

    assertEquals(await deleteBackup(projectDir, name), true);
    assertEquals(await listBackups(projectDir), []);
  } finally {
    await Deno.remove(projectDir, { recursive: true });
  }
});

Deno.test("pruning keeps the newest by the time in the name", async () => {
  const names = [
    "rift-backup-2026-09-10-0300.tar.gz",
    "rift-backup-2026-09-12-0300-encrypted.tar.gz",
    "rift-backup-2026-09-11-0300.tar.gz",
    "rift-backup-2026-09-12-0300-2.tar.gz",
  ];
  const projectDir = await project(names);
  try {
    // Written last, so its mtime is the newest: an old backup copied back in.
    // It must still count as the oldest.
    await Deno.writeTextFile(
      join(projectDir, BACKUPS_DIR, "rift-backup-2026-01-01-0000.tar.gz"),
      "backup",
    );

    assertEquals(await pruneBackups(projectDir, 0), [], "zero must delete nothing");
    assertEquals(await pruneBackups(projectDir, 2), [
      "rift-backup-2026-09-11-0300.tar.gz",
      "rift-backup-2026-09-10-0300.tar.gz",
      "rift-backup-2026-01-01-0000.tar.gz",
    ]);
    assertEquals((await listBackups(projectDir)).map((file) => file.name), [
      "rift-backup-2026-09-12-0300-encrypted.tar.gz",
      "rift-backup-2026-09-12-0300-2.tar.gz",
    ]);
    assert(await Deno.stat(join(projectDir, ".env")));
    assert(await Deno.stat(join(projectDir, BACKUPS_DIR, "notes.tar.gz")));
  } finally {
    await Deno.remove(projectDir, { recursive: true });
  }
});

Deno.test("the start time is read from the name", () => {
  assertEquals(
    startedAt("rift-backup-2026-09-15-1203-encrypted.tar.gz")?.toISOString(),
    "2026-09-15T12:03:00.000Z",
  );
  assertEquals(startedAt("rift-backup-latest.tar.gz"), null);
});
