/**
 * What the console does for a configured stack each time it starts.
 *
 * Usually nothing: every step below is idempotent and quiet when there is
 * nothing to do. It exists for the start that is not routine — a server
 * brought back from a backup, where the project directory holds a compose file
 * and `.env` and nothing else, the functions volume is empty, and the database
 * has not been loaded yet. Restoring one the way the docs said failed at each
 * of those in turn; these are the same steps put right, in the order they
 * depend on each other.
 *
 *   1. **Configuration.** Whatever `volumes/` should hold is written from
 *      `.env`, before Postgres can start without its init scripts.
 *   2. **Endpoints.** Installed if missing, so the functions container has
 *      something to serve.
 *   3. **The stack.** Brought up the way the dashboard's Restart does — which
 *      leaves Caddy out for a stack behind somebody else's proxy — but only
 *      when nothing beyond the console exists yet. A stack an operator stopped
 *      on purpose stays stopped.
 *   4. **The schema.** Brought up to this release as before, unless there is no
 *      Rift schema at all. On a configured stack that means a restore waiting
 *      for its dump, and migrating it would put a fresh schema underneath one.
 */
import { restoreMissingConfig } from "./setup/config_files.ts";
import {
  functionSources,
  installFunctions,
  missingFunctions,
} from "./setup/functions.ts";
import type { Paths } from "./setup/run.ts";
import {
  composeProblem,
  restartService,
  serviceStatuses,
  startStack,
  waitForSettled,
} from "./docker.ts";
import {
  type PostgresTarget,
  queryRows,
  runSql,
  targetFromEnv,
  waitUntilReachable,
} from "./postgres.ts";
import { applyUpgrade, pendingWork } from "./upgrade.ts";
import { adminTarget } from "./setup/realtime.ts";
import { repairAttachmentMetadata } from "./storage_repair.ts";

/** How long to wait for Postgres once the stack is up. Pulling images is slow. */
const DATABASE_TIMEOUT_MS = 600_000;

export async function prepareStack(paths: Paths): Promise<void> {
  const written = await restoreMissingConfig(paths);
  if (written.length > 0) {
    console.log(`Wrote missing configuration from .env: ${written.join(", ")}`);
  }

  const sources = functionSources(paths);
  const missing = await missingFunctions(sources, paths.functionsTarget);
  if (missing.length > 0) {
    const report = await installFunctions(sources, paths.functionsTarget);
    console.log(`Installed ${report.installed.length} endpoints that were missing.`);
  }

  // Not while the compose run that started this container is still converging
  // the same project: two of those at once is not a defined thing.
  await waitForSettled();

  const statuses = await serviceStatuses();
  if (statuses.every((service) => service.name === "console")) {
    console.log("Nothing but the console is here yet — bringing the stack up.");
    const started = await startStack(["full"]);
    if (!started.ok) {
      console.log(`The stack is not fully up yet: ${composeProblem(started.stderr)}`);
    }
  } else if (missing.length > 0) {
    // A functions container that started before its endpoints existed keeps
    // failing to find them until it is recreated.
    await restartService("functions");
  }

  const target = targetFromEnv();
  if (!await waitUntilReachable(target, DATABASE_TIMEOUT_MS)) {
    console.error("Postgres did not come up. `docker compose logs db` will say why.");
    return;
  }

  if (!await hasRiftSchema(target)) {
    // Realtime's own role, which a dump from a running server names as the
    // owner of Realtime's tables. Realtime creates it in one of its migrations,
    // and a restored database says those have all run — so without this the
    // dump reports it missing fourteen times and those tables change owner.
    const role = await runSql(adminTarget(target), REALTIME_ADMIN_ROLE);
    if (!role.ok) console.error("Could not create Realtime's admin role:", role.error);
    console.log(
      "This database has no Rift schema. If you are restoring a backup, load the dump now, " +
        "restore the attachments, then run `docker compose --profile full restart`. " +
        "Nothing has been written to the database.",
    );
    return;
  }

  // Before anything else reads the attachments: a restored volume can have
  // every file and none of the metadata storage keeps beside them.
  try {
    const repair = await repairAttachmentMetadata(adminTarget(target));
    if (repair.repaired > 0) {
      console.log(`Put back the file metadata on ${repair.repaired} attachments.`);
    }
    if (repair.absent > 0) {
      console.log(`${repair.absent} attachments are in the database but not on disk.`);
    }
  } catch (error) {
    console.error("Could not check attachment metadata:", error);
  }

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
}

/**
 * Whether Rift's schema has ever been applied to this database.
 *
 * Asks about `servers` rather than the console's ledger: opening the dashboard
 * creates the ledger, so finding one says nothing about the schema.
 */
async function hasRiftSchema(target: PostgresTarget): Promise<boolean> {
  const rows = await queryRows(
    target,
    "SELECT to_regclass('public.servers') IS NOT NULL",
  );
  return rows[0] === "t";
}

/**
 * Realtime's admin role, as its `CreateRealtimeAdminAndMoveOwnership` migration
 * defines it, created only if it is not already there.
 */
const REALTIME_ADMIN_ROLE = `DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'supabase_realtime_admin') THEN
    CREATE ROLE supabase_realtime_admin WITH NOINHERIT NOLOGIN NOREPLICATION;
    GRANT supabase_realtime_admin TO postgres;
  END IF;
END
$$;`;
