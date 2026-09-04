/**
 * `deno task migrate` — the migrator with nothing else attached.
 *
 * The console calls the same functions from its own UI. This entry point
 * exists so a stack can be brought up to date, or inspected, without one:
 * during development, from a CI job, or by an operator whose console will not
 * start because the schema it wants is the thing that is missing.
 */
import { parseArgs } from "jsr:@std/cli@1/parse-args";
import { isReachable, targetFromEnv } from "../postgres.ts";
import { applyPlan, planMigrations } from "./runner.ts";

const USAGE = `
Apply Rift's schema migrations.

  migrate [options]

  --dir <path>     Where the .sql files are (default: /app/migrations)
  --status         Report what is applied and pending, change nothing
  --accept-drift   Re-record checksums for migrations whose files changed.
                   Development only: it makes the ledger agree with the files
                   without re-running them.
  --help
`;

/** Human-readable duration for a step that usually takes under a minute. */
function formatDuration(ms: number): string {
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(1)}s`;
}

async function main(): Promise<number> {
  const flags = parseArgs(Deno.args, {
    boolean: ["status", "accept-drift", "help"],
    string: ["dir"],
    default: { dir: "/app/migrations" },
  });

  if (flags.help) {
    console.log(USAGE.trim());
    return 0;
  }

  const target = targetFromEnv();
  if (!await isReachable(target)) {
    console.error(`Cannot reach Postgres at ${target.host}:${target.port}.`);
    return 1;
  }

  const plan = await planMigrations(target, flags.dir);

  if (flags.status) {
    console.log(`applied  ${plan.applied.length}`);
    console.log(`pending  ${plan.pending.length}`);
    for (const migration of plan.pending) console.log(`         ${migration.name}`);
    if (plan.drifted.length > 0) {
      console.log(`drifted  ${plan.drifted.length}`);
      for (const migration of plan.drifted) console.log(`         ${migration.name}`);
    }
    return plan.drifted.length > 0 ? 1 : 0;
  }

  if (plan.pending.length === 0 && plan.drifted.length === 0) {
    console.log(`Up to date — ${plan.applied.length} migrations applied.`);
    return 0;
  }

  let outcomes;
  try {
    outcomes = await applyPlan(target, plan, {
      acceptDrift: flags["accept-drift"],
      onProgress: (outcome) => {
        const mark = outcome.ok ? "ok  " : "FAIL";
        console.log(
          `${mark} ${outcome.migration.name}  ${formatDuration(outcome.durationMs)}`,
        );
      },
    });
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }

  const failure = outcomes.find((outcome) => !outcome.ok);
  if (failure) {
    console.error(`\n${failure.migration.name} failed and was rolled back:\n`);
    console.error(failure.error);
    return 1;
  }

  console.log(`\nApplied ${outcomes.length} migration(s).`);
  return 0;
}

if (import.meta.main) Deno.exit(await main());
