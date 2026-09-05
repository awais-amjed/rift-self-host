/**
 * Working out what a database still needs, and giving it to it.
 *
 * The rules, in the order they matter:
 *
 * 1. Files run in filename order, once each, ever.
 * 2. A file and its ledger entry are written in **one transaction**, so the
 *    two can never disagree about what happened.
 * 3. A file whose contents changed after it ran is an error, not a warning —
 *    see [MigrationPlan.drifted].
 * 4. The first failure stops the run. Later migrations assume earlier ones,
 *    so continuing past a failure only buries the real error under noise.
 */
import { encodeHex } from "jsr:@std/encoding@1/hex";
import { type PostgresTarget, runSql } from "../postgres.ts";
import { acceptDrift, ensureLedger, readLedger, recordStatement } from "./ledger.ts";

/** One `.sql` file on disk. */
export interface Migration {
  /** Filename including the extension — the ledger's primary key. */
  name: string;
  path: string;
  sql: string;
  checksum: string;
}

/** What a database needs, measured against the files on disk. */
export interface MigrationPlan {
  /** Recorded as applied, and unchanged since. Nothing to do. */
  applied: Migration[];
  /** Never applied here. Will run, in this order. */
  pending: Migration[];
  /**
   * Applied, but the file has changed since.
   *
   * Always a mistake in a released stack: the database was built by a
   * migration that no longer exists as written, so nobody can say what shape
   * it is in. During development, where a migration may legitimately be
   * rewritten in place before anyone else has it, [applyPlan] can be told to
   * accept the new checksums instead.
   */
  drifted: Migration[];
}

/** What happened to one migration during a run. */
export interface MigrationOutcome {
  migration: Migration;
  ok: boolean;
  durationMs: number;
  /** psql's stderr, when [ok] is false. */
  error?: string;
}

/** Read every `.sql` file in [directory], in filename order. */
export async function readMigrations(directory: string): Promise<Migration[]> {
  const files: Migration[] = [];

  for await (const entry of Deno.readDir(directory)) {
    if (!entry.isFile || !entry.name.endsWith(".sql")) continue;
    const path = `${directory}/${entry.name}`;
    const sql = await Deno.readTextFile(path);
    files.push({ name: entry.name, path, sql, checksum: await checksum(sql) });
  }

  // Filenames are zero-padded (`007_limits.sql`), so a plain sort is the
  // numeric order. `localeCompare` is not used on purpose — its collation
  // varies by locale, and the order migrations run in must not.
  files.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return files;
}

/** SHA-256 of a migration's text, hex-encoded. */
export async function checksum(sql: string): Promise<string> {
  const bytes = new TextEncoder().encode(sql);
  return encodeHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** Compare the files on disk with what [target] has recorded. */
export async function planMigrations(
  target: PostgresTarget,
  directory: string,
): Promise<MigrationPlan> {
  await ensureLedger(target);

  const onDisk = await readMigrations(directory);
  const recorded = new Map(
    (await readLedger(target)).map((entry) => [entry.name, entry.checksum]),
  );

  const plan: MigrationPlan = { applied: [], pending: [], drifted: [] };
  for (const migration of onDisk) {
    const previous = recorded.get(migration.name);
    if (previous === undefined) plan.pending.push(migration);
    else if (previous !== migration.checksum) plan.drifted.push(migration);
    else plan.applied.push(migration);
  }
  return plan;
}

/**
 * Apply everything in [plan.pending], reporting each as it finishes.
 *
 * Stops at the first failure. Refuses to start at all while anything has
 * drifted, unless [options.acceptDrift] says to re-record those checksums —
 * which changes the ledger to match the files without re-running them, and is
 * only ever right while a migration is still being written.
 */
export async function applyPlan(
  target: PostgresTarget,
  plan: MigrationPlan,
  options: {
    acceptDrift?: boolean;
    onProgress?: (outcome: MigrationOutcome) => void;
  } = {},
): Promise<MigrationOutcome[]> {
  if (plan.drifted.length > 0) {
    if (!options.acceptDrift) {
      const names = plan.drifted.map((m) => m.name).join(", ");
      throw new Error(
        `These migrations have changed since they ran here: ${names}. ` +
          `The database was built by versions of them that no longer exist, so ` +
          `applying anything on top would be guesswork.\n\n` +
          `If you know this database already matches the new files — because ` +
          `you applied them by hand, or because the change was made before ` +
          `anyone else had them — record that and carry on with:\n` +
          `  docker compose exec console deno run --allow-env --allow-read ` +
          `--allow-run=psql /app/src/migrations/cli.ts --accept-drift`,
      );
    }
    await acceptDrift(
      target,
      plan.drifted.map(({ name, checksum }) => ({ name, checksum })),
    );
  }

  const outcomes: MigrationOutcome[] = [];
  for (const migration of plan.pending) {
    const startedAt = performance.now();
    const result = await runSql(
      target,
      migration.sql + recordStatement(migration.name, migration.checksum),
      { singleTransaction: true },
    );
    const durationMs = performance.now() - startedAt;

    const outcome: MigrationOutcome = {
      migration,
      ok: result.ok,
      durationMs,
      error: result.ok ? undefined : result.error,
    };
    outcomes.push(outcome);
    options.onProgress?.(outcome);

    if (!result.ok) break;
  }

  return outcomes;
}
