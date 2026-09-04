/**
 * The console process.
 *
 * Starts before anything else in the stack exists, which is the whole point:
 * on a fresh machine `docker compose up -d` brings up this container alone,
 * and it is what creates the conditions for the rest.
 */
import { isDockerReachable, projectDir } from "./docker.ts";
import { configuredPassword } from "./web/auth.ts";
import { handle, isConfigured } from "./web/routes.ts";

const PORT = Number(Deno.env.get("CONSOLE_PORT") ?? "8080");

/**
 * Say the password on startup.
 *
 * `docker compose logs console` is the documented way to find it, and it is
 * the only way — the console has no other channel to an operator who has just
 * run one command. Printed on every start rather than only the first, because
 * the log it was printed to may well have been rotated away by the time
 * anybody looks.
 */
function announce(configured: boolean): void {
  const password = configuredPassword();
  const banner = "─".repeat(58);

  console.log(`\n${banner}`);
  console.log("  Rift console");
  console.log(`  http://localhost:${PORT}`);
  if (password) console.log(`  password: ${password}`);
  else if (!configured) {
    console.log("  No password yet — set one up at the address above.");
  }
  console.log(`${banner}\n`);
}

async function main(): Promise<void> {
  const configured = await isConfigured(projectDir());

  if (!await isDockerReachable()) {
    console.error(
      "Cannot reach the Docker socket. The console can do nothing without it —\n" +
        "check that /var/run/docker.sock is mounted into this container.",
    );
  }

  announce(configured);

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
