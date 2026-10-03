import { assertEquals } from "jsr:@std/assert@1";
import { run } from "./subprocess.ts";

// Far more than any pipe holds, so a `run` that writes all of its input before
// reading any output deadlocks here — the hang setup hit on a busy Docker host.
Deno.test("input larger than a pipe is not a deadlock", async () => {
  const input = "statement;\n".repeat(200_000);
  const result = await run("cat", [], { stdin: input, timeoutMs: 20_000 });
  assertEquals(result.code, 0);
  assertEquals(result.stdout.length, input.trim().length);
});

Deno.test("a child that exits without reading its input still reports", async () => {
  const result = await run("sh", ["-c", "echo refused >&2; exit 3"], {
    stdin: "x".repeat(1_000_000),
  });
  assertEquals(result.code, 3);
  assertEquals(result.stderr, "refused");
});
