/**
 * Bringing a stack up to the release the console image carries.
 *
 * A pull delivers new console code, new migrations and new endpoints all in
 * one image — but only the first of those runs by itself. Until this existed,
 * `docker compose pull && docker compose up -d` gave you a new console sitting
 * on an old schema serving old endpoints, with the dashboard showing a red
 * "schema out of date" row and no way to act on it.
 *
 * Three steps, in an order that matters, and one that only ever runs once:
 *
 *   1. **Endpoints first.** They are files; installing them is atomic enough
 *      and reversible by reinstalling. Nothing depends on them being new.
 *   2. **Then migrations.** Each is its own transaction and the runner stops
 *      at the first failure, so a bad one leaves the schema at a version some
 *      migration describes rather than half-way through one.
 *   3. **Then the functions container.** The edge runtime caches a worker per
 *      endpoint and expires it after about a minute — measured, not assumed —
 *      so an edited endpoint keeps serving old code for that long. Recreating
 *      closes the window in which new schema meets old code.
 *
 *   4. **LiveKit's webhook**, added to a `livekit.yaml` from before there was
 *      one (`setup/livekit_webhook.ts`), and LiveKit restarted to read it.
 *
 * Steps 3 and 4 are the only ones that touch a container, and they are why
 * [applyUpgrade] waits for compose to settle: the console runs during the very
 * `up -d` that started it, and two compose runs converging one project is
 * undefined.
 *
 * There is no switch for any of this, and that is deliberate. Somebody who
 * does not want a release does not pull it; having pulled one, the only states
 * worth being in are "applied" and "failed loudly". An opt-out only bought a
 * third — a new console serving old endpoints against an old schema, looking
 * for all the world like it had worked.
 */
import { restartService, waitForSettled } from "./docker.ts";
import { applyPlan, type MigrationPlan, planMigrations } from "./migrations/runner.ts";
import { compareVersions, isVersion } from "./update/releases.ts";
import { isReachable, type PostgresTarget } from "./postgres.ts";
import {
  functionSources,
  installFunctions,
  missingFunctions,
} from "./setup/functions.ts";
import { connectLivekit, ensureLivekitWebhook } from "./setup/livekit_webhook.ts";
import { type Paths } from "./setup/run.ts";
import { announceToAdmins } from "./update/notice.ts";
import {
  APPLIED_VERSION,
  clearState,
  imageVersion,
  LIVEKIT_RESTART_OWED,
  readState,
  UPDATE_AVAILABLE,
  writeState,
} from "./state.ts";

/** What this stack still needs. */
export interface PendingWork {
  /** The release recorded as applied here, or null before any upgrade. */
  appliedVersion: string | null;
  /** The release this console image carries. */
  imageVersion: string;
  /** Migrations in the image that this database has never run. */
  pendingMigrations: string[];
  /** Migrations that ran here and have since been edited — always a problem. */
  driftedMigrations: string[];
  /**
   * Endpoints this image carries that the functions volume does not have. A
   * restored server starts with none and a database already at this release,
   * so before this nothing counted as outstanding and every endpoint was gone.
   */
  missingEndpoints: string[];
  /**
   * Why this console must not apply itself here, when the database was
   * brought to a newer release than it carries: an older image put back by
   * hand. Applying would install older endpoints over a newer schema and
   * record the older version. Null when it may.
   */
  databaseNewer: string | null;
  /**
   * Whether anything at all is outstanding.
   *
   * A version mismatch counts even with no pending migrations: a release may
   * change only endpoints, and those have no ledger of their own.
   */
  needed: boolean;
}

/** One line of progress, for a page watching an upgrade run. */
export interface UpgradeProgress {
  step: string;
  detail?: string;
  done: boolean;
}

/** What an upgrade did. */
export interface UpgradeResult {
  installed: number;
  removed: string[];
  migrationsApplied: string[];
  /** False when the stack never settled and the restart was left undone. */
  endpointsRestarted: boolean;
  version: string;
}

/** Measure the gap between this image and this database. */
export async function pendingWork(
  target: PostgresTarget,
  paths: Paths,
): Promise<PendingWork> {
  const applied = await readState(target, APPLIED_VERSION);
  const image = imageVersion();
  const plan = await planMigrations(target, paths.migrationsDir);

  const pendingMigrations = plan.pending.map((m) => m.name);
  const driftedMigrations = plan.drifted.map((m) => m.name);
  const missingEndpoints = await missingFunctions(
    functionSources(paths),
    paths.functionsTarget,
  );
  const databaseNewer = newerDatabase(plan, applied, image);

  return {
    appliedVersion: applied,
    imageVersion: image,
    pendingMigrations,
    driftedMigrations,
    missingEndpoints,
    databaseNewer,
    needed: databaseNewer === null && (
      pendingMigrations.length > 0 ||
      driftedMigrations.length > 0 ||
      missingEndpoints.length > 0 ||
      applied !== image
    ),
  };
}

/**
 * Why [image] must not be applied over this database, or null. `runUpdate`
 * refuses to move to an older release; this is the same refusal for an older
 * image started by hand, which the start-up would otherwise apply.
 */
export function newerDatabase(
  plan: MigrationPlan,
  applied: string | null,
  image: string,
): string | null {
  const unknown = plan.unknown ?? [];
  if (unknown.length > 0) {
    return `This database has migrations this console does not (${
      unknown.join(", ")
    }): ` +
      `it was brought to a newer release than ${image}. Run that release's console ` +
      "image; a release cannot be taken back.";
  }
  if (
    applied !== null && isVersion(applied) && isVersion(image) &&
    compareVersions(applied, image) > 0
  ) {
    return `This database is at ${applied}, newer than this console's ${image}. Run ` +
      `the ${applied} console image; a release cannot be taken back.`;
  }
  return null;
}

/**
 * Apply everything this image carries.
 *
 * Throws on a failed migration rather than carrying on: every step after the
 * first assumes the ones before it, and an upgrade that half-happened is worth
 * stopping loudly.
 */
export async function applyUpgrade(
  target: PostgresTarget,
  paths: Paths,
  report: (progress: UpgradeProgress) => void = () => {},
): Promise<UpgradeResult> {
  const step = async <T>(name: string, work: () => Promise<T>): Promise<T> => {
    report({ step: name, done: false });
    const value = await work();
    report({ step: name, done: true });
    return value;
  };

  if (!await isReachable(target)) {
    throw new Error("The database is not reachable, so nothing was changed.");
  }

  // Everything that can refuse, before anything changes: a newer database, or
  // a migration edited since it ran (`applyPlan` refuses that before it runs
  // anything).
  const plan = await planMigrations(target, paths.migrationsDir);
  const newer = newerDatabase(
    plan,
    await readState(target, APPLIED_VERSION),
    imageVersion(),
  );
  if (newer !== null) throw new Error(newer);

  // The schema before the endpoints. The other way round, a migration that
  // failed on one server's data rolled back and left the new endpoints in
  // place, calling functions it had not created, on every start after. Old
  // endpoints on a new schema is the half-state that works: migrations add.
  const applied = await step("Applying the schema", async () => {
    const outcomes = await applyPlan(target, plan, {
      onProgress: (outcome) =>
        report({
          step: "Applying the schema",
          detail: outcome.migration.name,
          done: false,
        }),
    });
    const failure = outcomes.find((outcome) => !outcome.ok);
    if (failure) throw new Error(`${failure.migration.name} failed:\n${failure.error}`);
    return outcomes.map((outcome) => outcome.migration.name);
  });

  const installed = await step("Installing server endpoints", () =>
    installFunctions(
      functionSources(paths),
      paths.functionsTarget,
    ));

  // Only now, and only if compose is not still working on this project.
  const restarted = await step("Reloading endpoints", async () => {
    if (!await waitForSettled()) return false;
    const result = await restartService("functions");
    return result.ok;
  });

  // A stack set up before LiveKit had a webhook gets one, once. LiveKit reads
  // its file only as it starts, so calls drop for the moment it restarts.
  await step("Connecting LiveKit to the server", () =>
    connectLivekit({
      addWebhook: () => ensureLivekitWebhook(paths.projectDir),
      pending: async () => await readState(target, LIVEKIT_RESTART_OWED) !== null,
      setPending: (on) =>
        on
          ? writeState(target, LIVEKIT_RESTART_OWED, "webhook")
          : clearState(target, LIVEKIT_RESTART_OWED),
      settled: waitForSettled,
      restart: async () => (await restartService("livekit")).ok,
    }));

  const version = imageVersion();
  await step("Recording the version", () => writeState(target, APPLIED_VERSION, version));
  // What was said to be newer is this, or older: the next check says again
  // if something newer still is out (`update/notice.ts`). Not a step: a
  // notice left behind is no reason to call a finished update failed.
  await clearState(target, UPDATE_AVAILABLE)
    .then(() => announceToAdmins(target))
    .catch((error) => console.error("[update] clearing the update notice:", error));

  return {
    installed: installed.installed.length,
    removed: installed.removed,
    migrationsApplied: applied,
    endpointsRestarted: restarted,
    version,
  };
}
