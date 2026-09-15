import { assert, assertEquals } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import { BACKUPS_DIR, openBackup } from "./create.ts";

Deno.test("a download serves only files the backup list shows", async () => {
  // The name comes straight from the query string. Anything that is not a
  // listed backup — above all a path climbing out to `.env` — must be refused.
  const projectDir = await Deno.makeTempDir();
  try {
    await Deno.mkdir(join(projectDir, BACKUPS_DIR));
    const name = "rift-backup-2026-09-15-1203.tar.gz";
    await Deno.writeTextFile(join(projectDir, BACKUPS_DIR, name), "backup");
    await Deno.writeTextFile(join(projectDir, ".env"), "SECRET=1");
    await Deno.writeTextFile(join(projectDir, BACKUPS_DIR, "notes.tar.gz"), "x");

    const opened = await openBackup(projectDir, name);
    assert(opened, "a listed backup was refused");
    assertEquals(opened.bytes, 6);
    assertEquals(await new Response(opened.file.readable).text(), "backup");

    for (
      const refused of [
        "../.env",
        ".env",
        "notes.tar.gz",
        `../${BACKUPS_DIR}/${name}`,
        "",
      ]
    ) {
      assertEquals(await openBackup(projectDir, refused), null, `served ${refused}`);
    }
  } finally {
    await Deno.remove(projectDir, { recursive: true });
  }
});
