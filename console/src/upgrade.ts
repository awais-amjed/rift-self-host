/**
 * Bringing a stack up to the release the console image carries.
 *
 * A pull delivers new console code, new migrations and new endpoints all in
 * one image — but only the first of those runs by itself. Until this existed,
 * `docker compose pull && docker compose up -d` gave you a new console sitting
 * on an old schema serving old endpoints, with the dashboard showing a red
 * "schema out of date" row and no way to act on it.
 *
 * Three steps, in an order that matters:
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
 * Step 3 is the only one that touches a container, and it is why [applyUpgrade]
 * waits for compose to settle: the console runs during the very `up -d` that
 * started it, and two compose runs converging one project is undefined.
 *
 * There is no switch for any of this, and that is deliberate. Somebody who
 * does not want a release does not pull it; having pulled one, the only states
 * worth being in are "applied" and "failed loudly". An opt-out only bought a
 * third — a new console serving old endpoints against an old schema, looking
 * for all the world like it had worked.
 */
import { restartService, waitForSettled } from "./docker.ts";
import { applyPlan, planMigrations } from "./migrations/runner.ts";
import { isReachable, type PostgresTarget } from "./postgres.ts";
import {
  functionSources,
  installFunctions,
  missingFunctions,
} from "./setup/functions.ts";
import { type Paths } from "./setup/run.ts";
import { APPLIED_VERSION, imageVersion, readState, writeState } from "./state.ts";

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

  return {
    appliedVersion: applied,
    imageVersion: image,
    pendingMigrations,
    driftedMigrations,
    missingEndpoints,
    needed: pendingMigrations.length > 0 ||
      driftedMigrations.length > 0 ||
      missingEndpoints.length > 0 ||
      applied !== image,
  };
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

  const installed = await step("Installing server endpoints", () =>
    installFunctions(
      functionSources(paths),
      paths.functionsTarget,
    ));

  const applied = await step("Applying the schema", async () => {
    const plan = await planMigrations(target, paths.migrationsDir);
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

  // Only now, and only if compose is not still working on this project.
  const restarted = await step("Reloading endpoints", async () => {
    if (!await waitForSettled()) return false;
    const result = await restartService("functions");
    return result.ok;
  });

  const version = imageVersion();
  await step("Recording the version", () => writeState(target, APPLIED_VERSION, version));

  return {
    installed: installed.installed.length,
    removed: installed.removed,
    migrationsApplied: applied,
    endpointsRestarted: restarted,
    version,
  };
}
