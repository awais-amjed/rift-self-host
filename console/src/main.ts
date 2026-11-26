/**
 * The console process.
 *
 * Starts before anything else in the stack exists, which is the whole point:
 * on a fresh machine `docker compose up -d` brings up this container alone,
 * and it is what creates the conditions for the rest.
 */
import { removeBackupLeftovers } from "./backup/create.ts";
import { clearStaleLock, exclusively } from "./operation.ts";
import { announce, LISTEN_PORT } from "./banner.ts";
import { startScheduler } from "./backup/scheduler.ts";
import { startTopicRuleWatch } from "./setup/topic_rules.ts";
import { startAttachmentSweep } from "./attachment_sweep.ts";
import { startUpdateNotice } from "./update/notice.ts";
import { isDockerReachable } from "./docker.ts";
import { storedPasswordHash } from "./console_password.ts";
import { prepareStack, preparingState } from "./boot.ts";
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

  // A plain password left in .env — by a stack set up before the console kept
  // a hash, by hand, or by a restored backup — is hashed now rather than at
  // the next sign-in, so it does not sit in the file meanwhile.
  await storedPasswordHash().catch((error) =>
    console.error("Could not hash the console password:", error)
  );

  announce({ configured });

  // Everything a configured stack needs each time the console starts: missing
  // configuration and endpoints put back, a stack that was never brought up
  // brought up, and the release this image carries applied. See boot.ts. Not
  // awaited: it waits for compose and for Postgres, and the console has to be
  // answering requests long before either.
  // Whatever the last container was doing, it is doing it no longer.
  clearStaleLock(defaultPaths().projectDir);
  await removeBackupLeftovers(defaultPaths().projectDir).catch((error) =>
    console.error("Could not clear an interrupted backup's files:", error)
  );
  if (configured) {
    void exclusively(
      defaultPaths().projectDir,
      "getting the stack ready",
      () => prepareStack(defaultPaths()),
    ).catch((error) => console.error("Could not prepare the stack:", error));
  }

  // Started either way: each check asks whether setup has finished since. Never
  // while the stack is being prepared: a restore on a slow disk outlasted the
  // first check's five minutes, and a backup was made of a half-loaded database.
  startScheduler(
    defaultPaths().projectDir,
    () => isConfigured() && !preparingState().running,
  );
  startTopicRuleWatch(isConfigured);
  // The same guard: the database has to be there and settled to keep it in.
  startUpdateNotice(() => isConfigured() && !preparingState().running);
  // Files left behind by deleted messages, which only the service key can
  // remove. The apps asked for this until self-host 064.
  startAttachmentSweep(() => isConfigured() && !preparingState().running);

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
