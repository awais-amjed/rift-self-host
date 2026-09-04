/**
 * Raising Realtime's rate limits off the free-tier defaults.
 *
 * A stock `supabase/realtime` tenant allows 100 events per second, and that
 * ceiling counts **deliveries, not sends** — one broadcast to twenty
 * subscribers is twenty-one events. Measured on a development stack, ten
 * messages a second fanned out to twenty subscribers killed every channel with
 * "Too many messages per second" after about thirty seconds. Twenty to thirty
 * chatty members is enough to reach it.
 *
 * Two things make it miserable to diagnose, which is why it is done here
 * rather than left in a runbook:
 *
 * - The limit is a sixty-second rolling average, so bursts sail past and only
 *   sustained traffic trips it. A short test proves nothing.
 * - `postgres_changes` spends the same budget. The unread-badge subscriptions
 *   are server-wide, so they scale with members × messages and are usually the
 *   larger cost — not chat broadcasts, which is where anyone would look first.
 *
 * `SEED_SELF_HOST: "false"` in docker-compose.yml is the other half. Without
 * it the tenant row is deleted and reinserted on every boot with no `max_*`
 * fields, and this runs, works, and is undone by the next restart.
 */
import { FIELD_SEPARATOR, type PostgresTarget, queryRows, runSql } from "../postgres.ts";

/** What a Rift server is provisioned for. */
export interface RealtimeLimits {
  maxEventsPerSecond: number;
  maxBytesPerSecond: number;
  maxPresenceEventsPerSecond: number;
  maxConcurrentUsers: number;
  maxJoinsPerSecond: number;
}

/**
 * Room for a busy community server, not a guess at a hard ceiling.
 *
 * These are far above anything a single-server deployment reaches; the cost of
 * being generous is bounded by the machine, whereas the cost of being tight is
 * channels that die under load with a message about rate limits nobody
 * connects to a chat that has stopped updating.
 */
export const DEFAULT_LIMITS: RealtimeLimits = {
  maxEventsPerSecond: 5000,
  maxBytesPerSecond: 10_000_000,
  maxPresenceEventsPerSecond: 5000,
  maxConcurrentUsers: 1000,
  maxJoinsPerSecond: 500,
};

/** The tenant Realtime creates for itself, named after its container. */
export const TENANT = "realtime-dev";

/**
 * Connect as `supabase_admin`.
 *
 * `postgres` has no rights on the `_realtime` schema, and the failure is a
 * permission error on a table nobody expected to be touching.
 */
export function adminTarget(target: PostgresTarget): PostgresTarget {
  return { ...target, user: "supabase_admin" };
}

/** SQL for setting the limits. Exported so a health check can read it back. */
export function updateStatement(limits: RealtimeLimits): string {
  return `
UPDATE _realtime.tenants SET
  max_events_per_second          = ${limits.maxEventsPerSecond},
  max_bytes_per_second           = ${limits.maxBytesPerSecond},
  max_presence_events_per_second = ${limits.maxPresenceEventsPerSecond},
  max_concurrent_users           = ${limits.maxConcurrentUsers},
  max_joins_per_second           = ${limits.maxJoinsPerSecond}
WHERE external_id = '${TENANT}';
`;
}

/**
 * Apply [limits] to the tenant row.
 *
 * Returns false if the row does not exist yet — Realtime creates it on first
 * boot, so this has to run after the service is up, not before.
 */
export async function applyLimits(
  target: PostgresTarget,
  limits: RealtimeLimits = DEFAULT_LIMITS,
): Promise<boolean> {
  const admin = adminTarget(target);

  const existing = await queryRows(
    admin,
    `SELECT count(*) FROM _realtime.tenants WHERE external_id = '${TENANT}'`,
  );
  if (existing[0] !== "1") return false;

  const result = await runSql(admin, updateStatement(limits), {
    singleTransaction: true,
  });
  if (!result.ok) throw new Error(`Could not raise the realtime limits: ${result.error}`);
  return true;
}

/** What the tenant row currently says, for the health check. */
export async function currentLimits(
  target: PostgresTarget,
): Promise<RealtimeLimits | null> {
  const rows = await queryRows(
    adminTarget(target),
    `SELECT max_events_per_second, max_bytes_per_second,
            max_presence_events_per_second, max_concurrent_users,
            max_joins_per_second
     FROM _realtime.tenants WHERE external_id = '${TENANT}'`,
  );
  if (rows.length === 0) return null;

  const [events, bytes, presence, users, joins] = rows[0].split(FIELD_SEPARATOR).map(
    Number,
  );
  return {
    maxEventsPerSecond: events,
    maxBytesPerSecond: bytes,
    maxPresenceEventsPerSecond: presence,
    maxConcurrentUsers: users,
    maxJoinsPerSecond: joins,
  };
}
