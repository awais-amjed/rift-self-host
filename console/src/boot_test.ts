import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { preparingState, stepReporter, tracked } from "./boot.ts";

Deno.test("a step goes to the log and to whoever asked, once each", () => {
  const logged: string[] = [];
  const reported: string[] = [];
  const say = stepReporter((step) => reported.push(step), (step) => logged.push(step));

  say("Loading the database");

  assertEquals(logged, ["Loading the database"]);
  assertEquals(reported, ["Loading the database"]);
});

Deno.test("the dashboard hears what the start is doing, and how it ended", async () => {
  const seen: unknown[] = [];
  const reported: string[] = [];
  await tracked((report) => {
    seen.push(preparingState());
    report("Applying the schema");
    seen.push(preparingState());
    return Promise.resolve();
  }, (step) => reported.push(step));
  assertEquals(seen, [
    { running: true, step: null, failure: null },
    { running: true, step: "Applying the schema", failure: null },
  ]);
  assertEquals(reported, ["Applying the schema"]);
  assertEquals(preparingState(), { running: false, step: null, failure: null });

  await assertRejects(() =>
    tracked(() => Promise.reject(new Error("031_example.sql failed")))
  );
  assertEquals(preparingState(), {
    running: false,
    step: null,
    failure: "031_example.sql failed",
  });
});
