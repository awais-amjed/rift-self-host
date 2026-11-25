import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import { checkGzip, CLEAR_DEFAULT_PRIVILEGES, loadArgs } from "./restore.ts";
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
