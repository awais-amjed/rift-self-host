/**
 * The `rift_console` schema, created once per process by whoever needs it
 * first.
 *
 * Two tables live here — the migration ledger and the console's small facts —
 * and they used to create themselves independently, each running its own
 * `CREATE SCHEMA IF NOT EXISTS` and `REVOKE ALL ON SCHEMA` before every read.
 * Two problems with that, and the second one bit:
 *
 *  - A REVOKE on a schema rewrites its `pg_namespace` row whether or not the
 *    grants change. Run two at once — the dashboard reads the ledger and the
 *    state table in one breath — and Postgres refuses one of them with
 *    `tuple concurrently updated`. The read that lost came back as "no such
 *    value", so the dashboard reported the local-testing switch off while it
 *    was on.
 *  - It is a catalog write on the read path, ten seconds apart, forever.
 *
 * So: one owner, one statement, memoised, and skipped entirely once the tables
 * are there.
 *
 * Why its own schema at all: PostgREST is published with
 * `PGRST_DB_SCHEMAS: public,storage`, and Supabase grants new tables in
 * `public` to `authenticated` by default — so either table sitting there would
 * be readable, and probably writable, by anybody holding the anon key. Out of
 * the published schemas it is not reachable over the API whatever its grants
 * say; the REVOKE is the second line of defence rather than the first.
 */
import { type PostgresTarget, queryRows, runSql } from "./postgres.ts";

export const SCHEMA = "rift_console";

const CREATE = `
CREATE SCHEMA IF NOT EXISTS ${SCHEMA};

REVOKE ALL ON SCHEMA ${SCHEMA} FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS ${SCHEMA}.migrations (
  name       text PRIMARY KEY,
  checksum   text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ${SCHEMA}.state (
  key        text PRIMARY KEY,
  value      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ${SCHEMA}.migrations, ${SCHEMA}.state
  FROM PUBLIC, anon, authenticated;

COMMENT ON TABLE ${SCHEMA}.migrations IS
  'Which files in migrations/ have run here. Managed by the Rift console; do not edit by hand.';

COMMENT ON TABLE ${SCHEMA}.state IS
  'Small facts the Rift console keeps about this stack — the release last '
  'applied, and whether voice is currently pointed at a LAN address. Managed '
  'by the console; do not edit by hand.';
`;

/** Whether both tables are already here, so the DDL can be skipped. */
async function alreadyThere(target: PostgresTarget): Promise<boolean> {
  const rows = await queryRows(
    target,
    `SELECT to_regclass('${SCHEMA}.migrations') IS NOT NULL
        AND to_regclass('${SCHEMA}.state') IS NOT NULL`,
  );
  return rows[0] === "t";
}

async function create(target: PostgresTarget): Promise<void> {
  if (await alreadyThere(target)) return;
  const result = await runSql(target, CREATE, { singleTransaction: true });
  if (!result.ok) {
    throw new Error(`Could not create the ${SCHEMA} schema: ${result.error}`);
  }
}

let created: Promise<void> | null = null;

/**
 * Make sure the schema and both its tables exist.
 *
 * Memoised for the life of the process, so concurrent callers share one
 * attempt — and a failed attempt is forgotten rather than cached, because the
 * usual reason to fail is a database that has not finished starting.
 */
export function ensureConsoleSchema(target: PostgresTarget): Promise<void> {
  created ??= create(target).catch((error) => {
    created = null;
    throw error;
  });
  return created;
}
