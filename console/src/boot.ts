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
  recreateOutdated,
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
import { backupPresent, restoreFromBackup } from "./backup/restore.ts";
import { adminTarget } from "./setup/realtime.ts";
import { repairAttachmentMetadata } from "./storage_repair.ts";

/** How long to wait for Postgres once the stack is up. Pulling images is slow. */
const DATABASE_TIMEOUT_MS = 600_000;

/**
 * A function that says [step] in the log and hands it to [report].
 *
 * Its own function, with a test, because the first version of this was an
 * inline arrow whose `console.log` a find-and-replace had turned into a call to
 * itself — and the console died with a stack overflow on the first line of the
 * first restore anybody ran.
 */
export function stepReporter(
  report: (step: string) => void,
  log: (step: string) => void = console.log,
): (step: string) => void {
  return (step) => {
    log(step);
    report(step);
  };
}

export async function prepareStack(
  paths: Paths,
  report: (step: string) => void = () => {},
): Promise<void> {
  // The log and, during a restore from the console page, the page itself.
  const say = stepReporter(report);

  const written = await restoreMissingConfig(paths);
  if (written.length > 0) {
    report("Writing the configuration");
    console.log(`Wrote missing configuration from .env: ${written.join(", ")}`);
  }

  const sources = functionSources(paths);
  const missing = await missingFunctions(sources, paths.functionsTarget);
  if (missing.length > 0) {
    const installed = await installFunctions(sources, paths.functionsTarget);
    report("Installing the server's endpoints");
    console.log(`Installed ${installed.installed.length} endpoints that were missing.`);
  }

  // Not while the compose run that started this container is still converging
  // the same project: two of those at once is not a defined thing.
  await waitForSettled();

  const statuses = await serviceStatuses();
  if (statuses.every((service) => service.name === "console")) {
    report("Starting the server");
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

  // A `docker compose pull` delivers new images, and the documented
  // `docker compose up -d` after it only replaces the console. Everything else
  // is brought onto its new image here, one service at a time, and nothing is
  // recreated that has not actually changed.
  const updated = await recreateOutdated();
  if (updated.length > 0) {
    report("Updating services");
    console.log(`Updated to the images the compose file names: ${updated.join(", ")}`);
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

    if (!await backupPresent(paths.projectDir)) {
      console.log(
        "This database has no Rift schema. To restore a backup, extract the backup " +
          "file so its contents sit beside the compose file, then restart the console. " +
          "Nothing has been written to the database.",
      );
      return;
    }

    console.log("Found a backup beside the compose file — restoring it.");
    const restored = await restoreFromBackup(paths.projectDir, say);
    if (restored.databaseErrors.length > 0) {
      console.error(
        `Loading the database printed ${restored.databaseErrors.length} errors:`,
        restored.databaseErrors.slice(0, 5).join("\n"),
      );
    }
    console.log("The backup is restored.");
  }

  report("Checking the attachments");

  // Before anything else reads the attachments: a restored volume can have
  // every file and none of the metadata storage keeps beside them.
  try {
    const repair = await repairAttachmentMetadata(adminTarget(target));
    if (repair.repaired > 0) {
      console.log(`Put back the file metadata on ${repair.repaired} attachments.`);
    }
    if (repair.absent > 0) {
      say(`${repair.absent} attachments are in the database but not on disk.`);
    }
  } catch (error) {
    console.error("Could not check attachment metadata:", error);
  }

  const work = await pendingWork(target, paths);
  if (!work.needed) return;

  say(
    `Applying ${work.imageVersion} (this stack is at ` +
      `${work.appliedVersion ?? "an unrecorded version"})`,
  );
  const result = await applyUpgrade(target, paths, (progress) => {
    if (progress.done) say(`  ${progress.step}`);
  });
  if (!result.endpointsRestarted) {
    say(
      "  Endpoints were installed but not reloaded — compose was still busy. " +
        "They take effect within a minute, or press Apply in the console.",
    );
  }
  say(`Now at ${result.version}.`);
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
