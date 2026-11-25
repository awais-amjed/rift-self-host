import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import { join } from "jsr:@std/path@1";
import { acquire, clearStaleLock, currentOperation, OperationBusy } from "./operation.ts";

Deno.test("one change at a time, and the lock goes with it", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const release = acquire(dir, "replacing keys");
    assertEquals(currentOperation(dir), "replacing keys");
    const busy = assertThrows(() => acquire(dir, "updating"), OperationBusy);
    assertEquals(busy.running, "replacing keys");
    release();
    assertEquals(currentOperation(dir), null);
    acquire(dir, "updating")();
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a lock its holder stopped refreshing is taken over", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(
      join(dir, ".console-operation.lock"),
      JSON.stringify({ pid: 4242, name: "updating", beat: Date.now() - 5 * 60_000 }),
    );
    assertEquals(currentOperation(dir), null);
    acquire(dir, "making a backup")();
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a lock another process keeps fresh refuses, until the console starts", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(
      join(dir, ".console-operation.lock"),
      JSON.stringify({ pid: 4242, name: "updating", beat: Date.now() }),
    );
    assertEquals(currentOperation(dir), "updating");
    assertThrows(() => acquire(dir, "replacing keys"), OperationBusy);
    clearStaleLock(dir);
    assertEquals(currentOperation(dir), null);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
