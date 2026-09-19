/**
 * The checks that catch this stack's silent failures.
 *
 * Every one of these has cost somebody a day, and none of them announces
 * itself: the server starts, the containers are green, and something specific
 * is broken in a way that surfaces hours or weeks later as "voice does not
 * work" or "the chat stopped updating". A dashboard that only repeated what
 * `docker ps` says would be worth nothing; this is the part that is worth
 * something.
 */
import { type PostgresTarget, queryRows } from "./postgres.ts";
import { planMigrations } from "./migrations/runner.ts";
import { currentLimits, DEFAULT_LIMITS } from "./setup/realtime.ts";

/** How a check came out. */
export type CheckLevel = "ok" | "warn" | "fail" | "unknown";

/** One answered question about the stack. */
export interface Check {
  name: string;
  level: CheckLevel;
  /** One sentence. Says what is wrong and what it will look like. */
  detail: string;
}

/** Run everything that can be answered from the database. */
export async function runChecks(
  target: PostgresTarget,
  migrationsDir: string,
): Promise<Check[]> {
  const checks = await Promise.all([
    schemaCheck(target, migrationsDir),
    realtimeLimitsCheck(target),
    tableSecurityCheck(target),
    cronCheck(target),
  ]);
  return checks;
}

/** Is the database at the schema this console ships? */
async function schemaCheck(
  target: PostgresTarget,
  migrationsDir: string,
): Promise<Check> {
  const name = "Schema up to date";
  try {
    const plan = await planMigrations(target, migrationsDir);
    if (plan.drifted.length > 0) {
      return {
        name,
        level: "fail",
        detail: `${plan.drifted.length} migration(s) changed after they ran here. ` +
          "This database was built by versions that no longer exist.",
      };
    }
    if (plan.pending.length > 0) {
      return {
        name,
        level: "warn",
        detail: `${plan.pending.length} migration(s) not yet applied. ` +
          "Features added in this release will fail until they are.",
      };
    }
    return { name, level: "ok", detail: `${plan.applied.length} migrations applied.` };
  } catch (error) {
    return { name, level: "unknown", detail: String(error) };
  }
}

/**
 * Are Realtime's limits still raised?
 *
 * The one check most likely to fire on a server that has been running for
 * months: `SEED_SELF_HOST` reverts these on restart, and the symptom is
 * channels dying under load with an error nobody connects to a chat that has
 * stopped updating.
 */
async function realtimeLimitsCheck(target: PostgresTarget): Promise<Check> {
  const name = "Realtime limits raised";
  try {
    const limits = await currentLimits(target);
    if (limits === null) {
      return {
        name,
        level: "unknown",
        detail: "Realtime has not created its tenant yet.",
      };
    }
    if (limits.maxEventsPerSecond < DEFAULT_LIMITS.maxEventsPerSecond) {
      return {
        name,
        level: "fail",
        detail: `Back to ${limits.maxEventsPerSecond} events/second. That counts ` +
          "deliveries, not sends — one message to everybody online is one event " +
          "each — and over the limit they are dropped without a word in any log. " +
          "Check SEED_SELF_HOST is false and re-run setup's realtime step.",
      };
    }
    // Checked too, because the two are set together and raising one alone
    // achieves nothing: events are spent per person online, so the ceiling
    // on people is half of what the ceiling on events means.
    if (limits.maxConcurrentUsers < DEFAULT_LIMITS.maxConcurrentUsers) {
      return {
        name,
        level: "fail",
        detail: `Back to ${limits.maxConcurrentUsers} concurrent users. Past that, ` +
          "a client's WebSocket is refused with no reason given, which looks " +
          "like a network fault. Check SEED_SELF_HOST is false and re-run " +
          "setup's realtime step.",
      };
    }
    return {
      name,
      level: "ok",
      detail:
        `${limits.maxEventsPerSecond} events/second, ${limits.maxConcurrentUsers} users.`,
    };
  } catch (error) {
    return { name, level: "unknown", detail: String(error) };
  }
}

/**
 * Is anything readable with only the anon key?
 *
 * This is not hypothetical. `messages` and `dm_messages` were once world-
 * readable *and* world-deletable on every server, because the migration that
 * created them did not enable RLS and Supabase grants new tables to
 * `authenticated` by default.
 */
async function tableSecurityCheck(target: PostgresTarget): Promise<Check> {
  const name = "Every table has row-level security";
  try {
    // Scoped to `public` because that, with `storage`, is what PostgREST
    // publishes — a table outside those schemas is unreachable over the API
    // whatever its grants say, which is why the console keeps its own ledger
    // in `rift_console`.
    const rows = await queryRows(
      target,
      `SELECT tablename FROM pg_tables
       WHERE schemaname = 'public' AND rowsecurity = false
       ORDER BY tablename`,
    );
    const unprotected = rows.filter((row) => row.length > 0);
    if (unprotected.length > 0) {
      return {
        name,
        level: "fail",
        detail: `Without RLS: ${unprotected.join(", ")}. Anyone holding this ` +
          "server's anon key can read them, and possibly write them.",
      };
    }
    return { name, level: "ok", detail: "No public table is missing RLS." };
  } catch (error) {
    return { name, level: "unknown", detail: String(error) };
  }
}

/** Are the cleanup jobs scheduled? */
async function cronCheck(target: PostgresTarget): Promise<Check> {
  const name = "Cleanup jobs scheduled";
  try {
    const rows = await queryRows(target, "SELECT count(*) FROM cron.job");
    const count = Number(rows[0] ?? "0");
    if (count === 0) {
      return {
        name,
        level: "warn",
        detail: "No scheduled jobs. Expired invites, old messages and orphaned " +
          "attachments will accumulate.",
      };
    }
    return { name, level: "ok", detail: `${count} scheduled.` };
  } catch (error) {
    return { name, level: "unknown", detail: String(error) };
  }
}
