/**
 * The console process.
 *
 * Starts before anything else in the stack exists, which is the whole point:
 * on a fresh machine `docker compose up -d` brings up this container alone,
 * and it is what creates the conditions for the rest.
 */
import { announce, consolePort } from "./banner.ts";
import { isDockerReachable, projectDir } from "./docker.ts";
import { configuredPassword } from "./web/auth.ts";
import { handle, isConfigured } from "./web/routes.ts";

const PORT = consolePort();

async function main(): Promise<void> {
  const configured = await isConfigured(projectDir());

  if (!await isDockerReachable()) {
    console.error(
      "Cannot reach the Docker socket. The console can do nothing without it —\n" +
        "check that /var/run/docker.sock is mounted into this container.",
    );
  }

  announce({ password: configuredPassword(), configured });

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
