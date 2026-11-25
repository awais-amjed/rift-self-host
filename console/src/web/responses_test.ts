import { assertEquals } from "jsr:@std/assert@1";
import { progressStream } from "./responses.ts";

Deno.test("work behind a progress stream runs to its end after the page goes", async () => {
  let finished = false;
  let resume!: () => void;
  const paused = new Promise<void>((resolve) => resume = resolve);
  const response = progressStream(async (send) => {
    send({ step: "one" });
    await paused;
    send({ step: "two" }); // after the reader has gone: must not throw
    finished = true;
  });
  const reader = response.body!.getReader();
  await reader.read();
  await reader.cancel("page closed");
  resume();
  for (let i = 0; i < 50 && !finished; i++) await new Promise((r) => setTimeout(r, 5));
  assertEquals(finished, true);
});
