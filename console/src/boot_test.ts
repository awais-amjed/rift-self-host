import { assertEquals } from "jsr:@std/assert@1";
import { stepReporter } from "./boot.ts";

Deno.test("a step goes to the log and to whoever asked, once each", () => {
  const logged: string[] = [];
  const reported: string[] = [];
  const say = stepReporter((step) => reported.push(step), (step) => logged.push(step));

  say("Loading the database");

  assertEquals(logged, ["Loading the database"]);
  assertEquals(reported, ["Loading the database"]);
});
