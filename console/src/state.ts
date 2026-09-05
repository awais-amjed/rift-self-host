/**
 * What this stack has actually been brought to, as opposed to what is sitting
 * in the console image.
 *
 * The distinction is the whole reason this exists. Pulling a new image gets
 * you new console code and nothing else — the migrations and endpoints it
 * carries are inert until something applies them. Without a record of what was
 * last applied, a console cannot tell an upgraded stack from one that has
 * merely been restarted, and so cannot know whether it has work to do.
 *
 * Kept in the `rift_console` schema beside the migration ledger, and for the
 * same reason: PostgREST publishes `public`, and Supabase grants new tables
 * there to `authenticated` by default.
 */
import { literal, type PostgresTarget, queryRows, runSql } from "./postgres.ts";

const SCHEMA = "rift_console";

const CREATE_STATE = `
CREATE SCHEMA IF NOT EXISTS ${SCHEMA};
REVOKE ALL ON SCHEMA ${SCHEMA} FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS ${SCHEMA}.state (
  key        text PRIMARY KEY,
  value      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ${SCHEMA}.state FROM PUBLIC, anon, authenticated;

COMMENT ON TABLE ${SCHEMA}.state IS
  'Small facts the Rift console keeps about this stack — the release last '
  'applied, and when. Managed by the console; do not edit by hand.';
`;

/** The release that last finished applying itself here. */
export const APPLIED_VERSION = "applied_version";

/** Create the table if this database has never had one. */
export async function ensureState(target: PostgresTarget): Promise<void> {
  const result = await runSql(target, CREATE_STATE, { singleTransaction: true });
  if (!result.ok) throw new Error(`Could not create console state: ${result.error}`);
}

/** Read one value, or null if it has never been set. */
export async function readState(
  target: PostgresTarget,
  key: string,
): Promise<string | null> {
  await ensureState(target);
  const rows = await queryRows(
    target,
    `SELECT value FROM ${SCHEMA}.state WHERE key = ${literal(key)}`,
  );
  return rows.length > 0 ? rows[0] : null;
}

/** Write one value. */
export async function writeState(
  target: PostgresTarget,
  key: string,
  value: string,
): Promise<void> {
  await ensureState(target);
  const result = await runSql(
    target,
    `INSERT INTO ${SCHEMA}.state (key, value)
     VALUES (${literal(key)}, ${literal(value)})
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();`,
    { singleTransaction: true },
  );
  if (!result.ok) throw new Error(`Could not record console state: ${result.error}`);
}

/**
 * The release this image is, read from the file baked in at build time.
 *
 * Falls back to `unknown` rather than throwing: a console that cannot name its
 * own version should still run, and an unknown version simply never matches
 * what is recorded, so it errs towards offering to apply rather than towards
 * claiming to be current.
 */
export function imageVersion(): string {
  try {
    return Deno.readTextFileSync("/app/VERSION").trim() || "unknown";
  } catch {
    return "unknown";
  }
}
