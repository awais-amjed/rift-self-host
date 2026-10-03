/**
 * The console process.
 *
 * Starts before anything else in the stack exists, which is the whole point:
 * on a fresh machine `docker compose up -d` brings up this container alone,
 * and it is what creates the conditions for the rest.
 */
import { announce, LISTEN_PORT } from "./banner.ts";
import { startScheduler } from "./backup/scheduler.ts";
import { startTopicRuleWatch } from "./setup/topic_rules.ts";
import { isDockerReachable } from "./docker.ts";
import { configuredPassword } from "./web/auth.ts";
import { prepareStack } from "./boot.ts";
import { defaultPaths } from "./setup/run.ts";
import { handle } from "./web/routes.ts";
import { isConfigured } from "./web/stack_state.ts";

const PORT = LISTEN_PORT;

async function main(): Promise<void> {
  const configured = isConfigured();

  if (!await isDockerReachable()) {
    console.error(
      "Cannot reach the Docker socket. The console can do nothing without it —\n" +
        "check that /var/run/docker.sock is mounted into this container.",
    );
  }

  announce({ password: configuredPassword(), configured });

  // Everything a configured stack needs each time the console starts: missing
  // configuration and endpoints put back, a stack that was never brought up
  // brought up, and the release this image carries applied. See boot.ts. Not
  // awaited: it waits for compose and for Postgres, and the console has to be
  // answering requests long before either.
  if (configured) {
    void prepareStack(defaultPaths()).catch((error) =>
      console.error("Could not prepare the stack:", error)
    );
  }

  // Started either way: each check asks whether setup has finished since.
  startScheduler(defaultPaths().projectDir, isConfigured);
  startTopicRuleWatch(isConfigured);

  Deno.serve({
    port: PORT,
    hostname: "0.0.0.0", // the published port is what binds to the loopback
    onListen: () => {},
  }, async (request) => {
    try {
      return await handle(request);
    } catch (error) {
      console.error("Unhandled:", error);
      return new Response(
        JSON.stringify({ error: error instanceof Error ? error.message : String(error) }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }
  });
}

if (import.meta.main) await main();
