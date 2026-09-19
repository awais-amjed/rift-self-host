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
 * - Every delivery spends it, database broadcasts included. A message in an
 *   open channel goes to the whole server's topic (migration 017), so the
 *   unread badges scale with members × messages and are usually the larger
 *   cost — not typing indicators, which is where anyone would look first.
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
  maxChannelsPerClient: number;
}

/**
 * Sized from measurement, not from the shape of the free tier.
 *
 * The previous values were "far above anything a single-server deployment
 * reaches". They were not. Load-tested against a real stack with real
 * clients — a 20,000-member server, sockets held open and messages written
 * to the database — the old numbers were reached by an ordinary busy
 * evening, and the way they fail is the worst possible one.
 *
 * **Events are deliveries.** A message in an open channel goes to the
 * server's topic (migration 017), so one send to 1,000 people online is
 * 1,000 events. At the old 5,000 that is **five messages a second, for the
 * whole server**, and the limit is a sixty-second rolling average, so a
 * burst sails through and only sustained traffic trips it.
 *
 * **And it drops them in silence.** The same test, 1,000 listeners and ten
 * messages a second for ninety seconds, twice, changing nothing but this
 * number:
 *
 *   max_events_per_second =   5,000 ..... 340,000 of 900,000 delivered
 *   max_events_per_second = 500,000 ..... 900,000 of 900,000 delivered
 *
 * Nothing was logged either time. No error reached a client, no warning
 * reached the server's log: 62% of messages simply never arrived, and every
 * client looked like it was working.
 *
 * What the numbers below are anchored to:
 *
 * - **Events.** The test machine (20 cores) sustained ~97,000 deliveries a
 *   second with nothing dropped. 200,000 is set above what the hardware can
 *   do on purpose, so the machine is the limit and this is a backstop rather
 *   than a silent ceiling. A server that genuinely cannot keep up will fall
 *   behind visibly instead of discarding messages quietly.
 * - **Users.** ~85–230 KB of Realtime memory per connection, so 10,000
 *   connections is about 1.6 GB — which is also where `RLIMIT_NOFILE` in
 *   docker-compose.yml is set, and raising either alone achieves nothing.
 *   A host with less memory should lower both together.
 * - **Joins.** A restart reconnects everybody at once, so this wants to be
 *   a good fraction of the connection count or coming back up is a thundering
 *   herd against its own rate limit.
 * - **Topics per client.** A member holds one for the server, one of their
 *   own, presence, voice, the open channel's typing — and since migration
 *   027 one per *private* channel they can see, because that is where a
 *   private channel's messages are announced. The stock 100 is therefore a
 *   cap on private channels per member, and reaching it looks like a channel
 *   that has silently stopped updating.
 */
export const DEFAULT_LIMITS: RealtimeLimits = {
  maxEventsPerSecond: 200_000,
  maxBytesPerSecond: 100_000_000,
  maxPresenceEventsPerSecond: 50_000,
  maxConcurrentUsers: 10_000,
  maxJoinsPerSecond: 5_000,
  maxChannelsPerClient: 1_000,
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
  max_joins_per_second           = ${limits.maxJoinsPerSecond},
  max_channels_per_client        = ${limits.maxChannelsPerClient}
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
            max_joins_per_second, max_channels_per_client
     FROM _realtime.tenants WHERE external_id = '${TENANT}'`,
  );
  if (rows.length === 0) return null;

  const [events, bytes, presence, users, joins, channels] = rows[0]
    .split(FIELD_SEPARATOR).map(Number);
  return {
    maxEventsPerSecond: events,
    maxBytesPerSecond: bytes,
    maxPresenceEventsPerSecond: presence,
    maxConcurrentUsers: users,
    maxJoinsPerSecond: joins,
    maxChannelsPerClient: channels,
  };
}
