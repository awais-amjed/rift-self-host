import { assert, assertEquals } from "jsr:@std/assert@1";
import { recreateArgs } from "./docker.ts";

Deno.test("recreating a service leaves what it depends on running", () => {
  // Kong depends on auth and rest, and both on Postgres. Without --no-deps,
  // recreating Kong recreated the database and dropped every connection.
  const args = recreateArgs("kong");
  assert(args.includes("--no-deps"));
  // And still a recreate rather than a restart, which would keep the
  // environment the container was created with and ignore a changed .env.
  assert(args.includes("--force-recreate"));
  assertEquals(args.at(-1), "kong");
});
