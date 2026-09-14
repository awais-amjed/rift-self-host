import { assert, assertEquals } from "jsr:@std/assert@1";
import { outdatedServices, recreateArgs, type ServiceStatus, upArgs } from "./docker.ts";

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

Deno.test("bringing the stack up never recreates what is already there", () => {
  // Compose's own "out of date" differs between versions, so a container an
  // operator started with the host's compose was recreated by the console's.
  const args = upArgs(["full"], ["db", "kong"]);
  assert(args.includes("--no-recreate"));
  assertEquals(args.slice(-2), ["db", "kong"]);
});

const running = (name: string, image: string): ServiceStatus => ({
  name,
  image,
  state: "running",
  health: "healthy",
  status: "Up",
});

Deno.test("a service is out of date only when its image name has changed", () => {
  const wanted = {
    db: "supabase/postgres:17.6.1.136",
    livekit: "livekit/livekit-server:v1.9",
    console: "riftapp/rift-console:latest",
  };
  const containers = [
    running("db", "supabase/postgres:17.6.1.136"),
    running("livekit", "livekit/livekit-server:v1.8"),
    // Replacing the console is the operator's own `docker compose up -d`.
    running("console", "riftapp/rift-console:0.1.0"),
    // Not in the compose file's full profile, so not this function's business.
    running("studio", "supabase/studio:old"),
  ];
  assertEquals(outdatedServices(wanted, containers), ["livekit"]);
});
