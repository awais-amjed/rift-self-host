/**
 * The record of which migrations a database has already run.
 *
 * Until this existed, migrations were applied by a shell loop over `*.sql` and
 * nothing was written down. That is survivable while the only server is a
 * development box you can drop and rebuild; it stops being survivable the
 * moment somebody else runs one, because there is then no way to ask a
 * database what it is, and no way to ship it a schema change.
 *
 * The table is created by the migrator itself rather than by `001_schema.sql`,
 * because it has to exist *before* the first migration in order to record it.
 */
import {
  FIELD_SEPARATOR,
  literal,
  type PostgresTarget,
  queryRows,
  runSql,
} from "../postgres.ts";

/** What the ledger says about one applied migration. */
export interface LedgerEntry {
  name: string;
  /** SHA-256 of the file as it was when it ran. */
  checksum: string;
}

/**
 * The ledger lives in its own schema, not in `public`.
 *
 * PostgREST is published with `PGRST_DB_SCHEMAS: public,storage`, and Supabase
 * grants new tables in `public` to `authenticated` by default — so a ledger
 * there would be readable, and probably writable, by every member of the
 * server holding nothing but its anon key. Out of the published schemas it is
 * not reachable over the API at all, whatever its grants say. The REVOKE is
 * the second line of defence rather than the first.
 */
const LEDGER_SCHEMA = "rift_console";

const CREATE_LEDGER = `
CREATE SCHEMA IF NOT EXISTS ${LEDGER_SCHEMA};

REVOKE ALL ON SCHEMA ${LEDGER_SCHEMA} FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS ${LEDGER_SCHEMA}.migrations (
  name       text PRIMARY KEY,
  checksum   text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ${LEDGER_SCHEMA}.migrations FROM PUBLIC, anon, authenticated;

COMMENT ON TABLE ${LEDGER_SCHEMA}.migrations IS
  'Which files in migrations/ have run here. Managed by the Rift console; do not edit by hand.';
`;

/** Create the ledger if this database has never had one. */
export async function ensureLedger(target: PostgresTarget): Promise<void> {
  const result = await runSql(target, CREATE_LEDGER, { singleTransaction: true });
  if (!result.ok) {
    throw new Error(`Could not create the migration ledger: ${result.error}`);
  }
}

/** Every migration this database has recorded, oldest first. */
export async function readLedger(target: PostgresTarget): Promise<LedgerEntry[]> {
  const rows = await queryRows(
    target,
    `SELECT name, checksum FROM ${LEDGER_SCHEMA}.migrations ORDER BY name`,
  );
  return rows.map((row) => {
    const [name, checksum] = row.split(FIELD_SEPARATOR);
    return { name, checksum };
  });
}

/**
 * The statement that records [name] as applied.
 *
 * Returned as SQL rather than executed, so a caller can append it to the
 * migration's own text and send both as one transaction. Recording separately
 * would leave a window where a crash makes an applied migration look pending,
 * and running it twice is how a schema ends up half-described.
 */
export function recordStatement(name: string, checksum: string): string {
  return `
INSERT INTO ${LEDGER_SCHEMA}.migrations (name, checksum)
VALUES (${literal(name)}, ${literal(checksum)});
`;
}

/** Update a recorded checksum in place, without re-running the migration. */
export async function acceptDrift(
  target: PostgresTarget,
  entries: LedgerEntry[],
): Promise<void> {
  if (entries.length === 0) return;
  const statements = entries
    .map((e) =>
      `UPDATE ${LEDGER_SCHEMA}.migrations SET checksum = ${literal(e.checksum)} ` +
      `WHERE name = ${literal(e.name)};`
    )
    .join("\n");
  const result = await runSql(target, statements, { singleTransaction: true });
  if (!result.ok) throw new Error(`Could not update the ledger: ${result.error}`);
}
