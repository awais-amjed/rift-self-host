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
import { targetFromEnv } from "./postgres.ts";
import { applyUpgrade, pendingWork } from "./upgrade.ts";
import { defaultPaths } from "./setup/run.ts";
import { handle, isConfigured } from "./web/routes.ts";

const PORT = consolePort();

async function main(): Promise<void> {
  const configured = isConfigured(projectDir());

  if (!await isDockerReachable()) {
    console.error(
      "Cannot reach the Docker socket. The console can do nothing without it —\n" +
        "check that /var/run/docker.sock is mounted into this container.",
    );
  }

  announce({ password: configuredPassword(), configured });

  // An upgrade arrives as a new image, and a new image only brings new console
  // code by itself — the migrations and endpoints it carries are inert until
  // something applies them. This is that something, so `docker compose pull &&
  // docker compose up -d` is the whole upgrade rather than the first half of
  // one. Not awaited: it waits for compose to finish converging the project,
  // and the console has to be answering requests long before then.
  if (configured) void applyPendingOnBoot();

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

/**
 * Bring the stack up to this image, if it is behind.
 *
 * Deliberately quiet when there is nothing to do, and deliberately loud when
 * it fails: a half-applied upgrade is worth a line in the log even though
 * nobody is watching one at the time. The dashboard shows the same state, and
 * the Apply button runs the same code.
 */
async function applyPendingOnBoot(): Promise<void> {
  try {
    const target = targetFromEnv();
    const paths = defaultPaths();
    const work = await pendingWork(target, paths);
    if (!work.needed) return;

    console.log(
      `Applying ${work.imageVersion} (this stack is at ` +
        `${work.appliedVersion ?? "an unrecorded version"})`,
    );
    const result = await applyUpgrade(target, paths, (progress) => {
      if (progress.done) console.log(`  ${progress.step}`);
    });

    if (!result.endpointsRestarted) {
      console.log(
        "  Endpoints were installed but not reloaded — compose was still busy. " +
          "They take effect within a minute, or press Apply in the console.",
      );
    }
    console.log(`Now at ${result.version}.`);
  } catch (error) {
    console.error("Could not apply this release:", error);
  }
}
