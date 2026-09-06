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
 * there to `authenticated` by default. The schema and this table are created
 * by [ensureConsoleSchema], which owns both of the schema's tables so that two
 * of them cannot race to revoke the same grants.
 */
import { literal, type PostgresTarget, queryRows, runSql } from "./postgres.ts";
import { ensureConsoleSchema, SCHEMA } from "./console_schema.ts";

/** The release that last finished applying itself here. */
export const APPLIED_VERSION = "applied_version";

/** Read one value, or null if it has never been set. */
export async function readState(
  target: PostgresTarget,
  key: string,
): Promise<string | null> {
  await ensureConsoleSchema(target);
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
  await ensureConsoleSchema(target);
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
 * Forget one value.
 *
 * Not the same as writing an empty string: a caller asks "has this ever been
 * set", and a fact that is over is one that was never set rather than one set
 * to nothing.
 */
export async function clearState(
  target: PostgresTarget,
  key: string,
): Promise<void> {
  await ensureConsoleSchema(target);
  const result = await runSql(
    target,
    `DELETE FROM ${SCHEMA}.state WHERE key = ${literal(key)};`,
    { singleTransaction: true },
  );
  if (!result.ok) throw new Error(`Could not clear console state: ${result.error}`);
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
