/**
 * The join rules for Rift's private Realtime topics.
 *
 * Members hear the database through broadcasts rather than Postgres Changes,
 * and every topic is private: a client may join `server:<id>` or `user:<id>` only
 * if `app.can_use_topic` says so. Realtime asks by checking a policy on its own
 * table, `realtime.messages`, and that is the awkward part:
 *
 * - The table belongs to `supabase_admin`. A migration runs as `postgres`,
 *   which may not put a policy on a table it does not own.
 * - Realtime creates the table itself, when the first client connects to it —
 *   on a new server that can be after the migrations have run, so there is
 *   nothing yet to attach a rule to.
 *
 * With no policy at all a private topic refuses everybody, and Realtime looks
 * simply broken: channels that never subscribe, no error anyone can read. So
 * the console installs the rules as `supabase_admin` at setup and at every
 * start, and keeps checking until the table exists to install them on.
 *
 * Each rule asks `app.can_use_topic` inside a subquery, so it runs once per
 * join rather than once per partition. The table is split by day, and
 * Realtime's join check selects its probe rows by id alone, so it reads every
 * partition. A condition that never mentions the row is checked once per
 * partition read: eleven partitions, eleven calls. Measured Oct 2 2026: with
 * a 0.2 s delay in the function a join took 2.2 s, which Realtime serves one at
 * a time per socket. The subquery is planned as an InitPlan, evaluated once.
 */
import { type PostgresTarget, queryRows, runSql, targetFromEnv } from "../postgres.ts";
import { adminTarget } from "./realtime.ts";

/** The two policies, by name — reading is joining, writing is sending. */
export const TOPIC_RULE_NAMES = ["rift_topic_read", "rift_topic_write"] as const;

/**
 * Written on each policy as its comment. A server whose rules carry another
 * one has an older shape and gets them made again, which is how a changed
 * rule reaches servers that already had the old one. Bump it with any change
 * to the SQL below.
 */
export const TOPIC_RULES_VERSION = "rift topic rules 2";

/**
 * Idempotent, and a no-op until Realtime has made its table. Dropped and made
 * again rather than skipped when present.
 */
export const TOPIC_RULES_SQL = `
DO $$
BEGIN
  IF to_regclass('realtime.messages') IS NULL THEN
    RETURN;
  END IF;
  DROP POLICY IF EXISTS rift_topic_read ON realtime.messages;
  CREATE POLICY rift_topic_read ON realtime.messages
    FOR SELECT TO authenticated
    USING ((SELECT app.can_use_topic(realtime.topic(), false)));
  COMMENT ON POLICY rift_topic_read ON realtime.messages IS '${TOPIC_RULES_VERSION}';
  DROP POLICY IF EXISTS rift_topic_write ON realtime.messages;
  CREATE POLICY rift_topic_write ON realtime.messages
    FOR INSERT TO authenticated
    WITH CHECK ((SELECT app.can_use_topic(realtime.topic(), true)));
  COMMENT ON POLICY rift_topic_write ON realtime.messages IS '${TOPIC_RULES_VERSION}';
END $$;`;

const COUNT_SQL = `SELECT count(*) FROM pg_policy p
  WHERE p.polrelid = to_regclass('realtime.messages')
    AND p.polname IN (${TOPIC_RULE_NAMES.map((name) => `'${name}'`).join(", ")})
    AND obj_description(p.oid, 'pg_policy') = '${TOPIC_RULES_VERSION}'`;

/** Whether both rules are in place, in their current shape. */
export async function topicRulesInstalled(target: PostgresTarget): Promise<boolean> {
  const rows = await queryRows(adminTarget(target), COUNT_SQL);
  return rows[0] === String(TOPIC_RULE_NAMES.length);
}

/**
 * Put the rules in place. False when Realtime has not made its table yet,
 * which is not a failure — [startTopicRuleWatch] tries again.
 */
export async function installTopicRules(target: PostgresTarget): Promise<boolean> {
  const result = await runSql(adminTarget(target), TOPIC_RULES_SQL, {
    singleTransaction: true,
  });
  if (!result.ok) throw new Error(`Could not install the topic rules: ${result.error}`);
  return await topicRulesInstalled(target);
}

const CHECK_MS = 30 * 1000;

/**
 * Keep the rules in place for as long as the console runs: installed once the
 * table first exists, again if anything ever takes them away, and again when
 * this console carries a newer shape than the server has.
 */
export function startTopicRuleWatch(isConfigured: () => boolean): void {
  let announced = false;
  const check = async () => {
    if (!isConfigured()) return;
    const target = targetFromEnv();
    if (await topicRulesInstalled(target)) return;
    if (await installTopicRules(target) && !announced) {
      announced = true;
      console.log("[realtime] topic rules installed");
    }
  };
  setInterval(() => {
    check().catch((error) => console.error("[realtime] topic rules:", error));
  }, CHECK_MS);
}
