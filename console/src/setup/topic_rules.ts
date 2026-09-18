/**
 * The join rules for Rift's private Realtime topics.
 *
 * Migration 017 moved members off Postgres Changes and onto broadcasts, and
 * made every topic private: a client may join `server:<id>` or `user:<id>` only
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
 */
import { type PostgresTarget, queryRows, runSql, targetFromEnv } from "../postgres.ts";
import { adminTarget } from "./realtime.ts";

/** The two policies, by name — reading is joining, writing is sending. */
export const TOPIC_RULE_NAMES = ["rift_topic_read", "rift_topic_write"] as const;

/**
 * Idempotent, and a no-op until Realtime has made its table. Dropped and made
 * again rather than skipped when present, so a changed rule reaches servers
 * that already had the old one.
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
    USING (app.can_use_topic(realtime.topic(), false));
  DROP POLICY IF EXISTS rift_topic_write ON realtime.messages;
  CREATE POLICY rift_topic_write ON realtime.messages
    FOR INSERT TO authenticated
    WITH CHECK (app.can_use_topic(realtime.topic(), true));
END $$;`;

const COUNT_SQL = `SELECT count(*) FROM pg_policies
  WHERE schemaname = 'realtime' AND tablename = 'messages'
    AND policyname IN (${TOPIC_RULE_NAMES.map((name) => `'${name}'`).join(", ")})`;

/** Whether both rules are in place. */
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
 * table first exists, and again if anything ever takes them away.
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
