import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import {
  checkGzip,
  CLEAR_DEFAULT_PRIVILEGES,
  loadArgs,
  openSealedBackup,
  STAGING_DIR,
} from "./restore.ts";
import { DATABASE_DUMP, MANIFEST, SEALED_FILE, sealPayload } from "./archive.ts";
import { parseDfAvailable } from "./create.ts";

async function gzipped(text: string): Promise<Uint8Array> {
  return new Uint8Array(
    await new Response(
      ReadableStream.from([new TextEncoder().encode(text)]).pipeThrough(
        new CompressionStream("gzip"),
      ),
    ).arrayBuffer(),
  );
}

Deno.test("a dump cut short is refused before anything loads", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const whole = await gzipped("SELECT 1;\n".repeat(5000));
    await Deno.writeFile(join(dir, "whole.sql.gz"), whole);
    await Deno.writeFile(join(dir, "cut.sql.gz"), whole.subarray(0, whole.length - 30));
    await checkGzip(join(dir, "whole.sql.gz"));
    await assertRejects(
      () => checkGzip(join(dir, "cut.sql.gz")),
      Error,
      "damaged or incomplete",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("the load is one transaction that stops at the first error", () => {
  const args = loadArgs();
  assertStringIncludes(args[4], "psql -q -1 -v ON_ERROR_STOP=1");
  // The default privileges go first, from the same stream.
  assertStringIncludes(args[4], `printf '%s\\n' "$1"; gunzip;`);
  assertEquals(args.at(-1), CLEAR_DEFAULT_PRIVILEGES);
});

Deno.test("df's available column is read in bytes", () => {
  const out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
    "/dev/sda1 1000000 400000 600000 40% /\n";
  assertEquals(parseDfAvailable(out), 600000 * 1024);
  assertEquals(parseDfAvailable("nonsense"), null);
});

async function exists(path: string): Promise<boolean> {
  return await Deno.stat(path).then(() => true, () => false);
}

Deno.test("an encrypted backup cut short leaves no .env, and can be opened again whole", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const parts = join(dir, "parts");
    await Deno.mkdir(parts);
    await Deno.writeTextFile(join(parts, "env"), "JWT_SECRET=x\n");
    await Deno.writeTextFile(
      join(parts, "manifest"),
      JSON.stringify({ encrypted: true }),
    );
    // Big enough to span frames, so cutting the end loses the last one.
    await Deno.writeFile(join(parts, "dump"), new Uint8Array(300_000).fill(7));
    const sealed = join(dir, "whole.sealed");
    await sealPayload(
      {
        ".env": join(parts, "env"),
        [MANIFEST]: join(parts, "manifest"),
        [DATABASE_DUMP]: join(parts, "dump"),
      },
      sealed,
      "pass phrase long",
      { iterations: 1000, chunkBytes: 64 * 1024 },
    );
    const whole = await Deno.readFile(sealed);

    const project = join(dir, "project");
    await Deno.mkdir(project);
    await Deno.writeFile(
      join(project, SEALED_FILE),
      whole.subarray(0, whole.length - 100),
    );
    await assertRejects(() => openSealedBackup(project, "pass phrase long"));
    assertEquals(await exists(join(project, ".env")), false);
    assertEquals(await exists(join(project, SEALED_FILE)), true);

    await Deno.writeFile(join(project, SEALED_FILE), whole);
    await openSealedBackup(project, "pass phrase long");
    assertEquals(await Deno.readTextFile(join(project, ".env")), "JWT_SECRET=x\n");
    assertEquals((await Deno.stat(join(project, DATABASE_DUMP))).size, 300_000);
    assertEquals(await exists(join(project, SEALED_FILE)), false);
    assertEquals(await exists(join(project, STAGING_DIR)), false);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
