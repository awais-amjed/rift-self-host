/**
 * Running SQL against the stack's Postgres.
 *
 * This shells out to `psql` rather than using a driver, and that is deliberate.
 * The migrations are 8,000 lines of schema written to be read by a human and
 * fed to `psql -f`: dollar-quoted function bodies, `CREATE EXTENSION`, `DO`
 * blocks. A driver using the extended query protocol refuses more than one
 * statement per call, so it would need a SQL splitter — and a SQL splitter that
 * gets `$$ ... $$` wrong corrupts a migration silently instead of failing.
 * `psql` already knows how to read SQL.
 */
import { setting } from "./env_file.ts";
import { run } from "./subprocess.ts";

/**
 * The character separating columns in [queryRows] output.
 *
 * ASCII unit separator: `psql` needs *some* delimiter, and every printable one
 * can legitimately occur inside a checksum comment or an error string.
 */
export const FIELD_SEPARATOR = "\x1F";

/** Where to connect. Assembled from the environment the console runs with. */
export interface PostgresTarget {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

/** The result of one `psql` invocation. */
export interface SqlResult {
  ok: boolean;
  /** stdout, trimmed. Empty for statements that return nothing. */
  output: string;
  /** stderr, trimmed. Where `ON_ERROR_STOP` puts the reason for a failure. */
  error: string;
}

/**
 * Connection details for the `db` service on the compose network.
 *
 * Read from the stack's `.env` rather than this process's environment — see
 * env_file.ts for why that distinction is load-bearing.
 *
 * `POSTGRES_HOST` defaults to the service name rather than `localhost`,
 * because inside a container `localhost` is the container.
 */
export function targetFromEnv(): PostgresTarget {
  return {
    host: setting("POSTGRES_HOST") ?? "db",
    port: Number(setting("POSTGRES_PORT") ?? "5432"),
    user: setting("POSTGRES_USER") ?? "postgres",
    password: setting("POSTGRES_PASSWORD") ?? "",
    database: setting("POSTGRES_DB") ?? "postgres",
  };
}

/** psql arguments and environment shared by every call. */
function invocation(
  target: PostgresTarget,
  args: string[],
): { args: string[]; env: Record<string, string> } {
  return {
    args: [
      "--host",
      target.host,
      "--port",
      String(target.port),
      "--username",
      target.user,
      "--dbname",
      target.database,
      "--no-password", // never block on a prompt; fail instead
      "--variable",
      "ON_ERROR_STOP=1",
      ...args,
    ],
    // Via the environment, so the password never appears in the process list.
    env: { PGPASSWORD: target.password },
  };
}

/**
 * Run [sql], optionally wrapped in a single transaction.
 *
 * `singleTransaction` is what makes a failed migration leave nothing behind:
 * without it `psql` autocommits statement by statement, so an error halfway
 * through a file leaves the schema in a state no migration describes.
 */
export async function runSql(
  target: PostgresTarget,
  sql: string,
  options: { singleTransaction?: boolean } = {},
): Promise<SqlResult> {
  const extra = options.singleTransaction ? ["--single-transaction"] : [];
  const { args, env } = invocation(target, [...extra, "--file", "-"]);

  const result = await run("psql", args, { env, stdin: sql });
  return { ok: result.code === 0, output: result.stdout, error: result.stderr };
}

/**
 * Run [sql] and return its rows unaligned and without headers, one per line.
 *
 * For reading the ledger and the health checks — anything whose answer is a
 * short table rather than a schema change.
 */
export async function queryRows(
  target: PostgresTarget,
  sql: string,
): Promise<string[]> {
  const { args, env } = invocation(target, [
    "--tuples-only",
    "--no-align",
    "--field-separator",
    FIELD_SEPARATOR,
    "--command",
    sql,
  ]);

  const result = await run("psql", args, { env });
  if (result.code !== 0) throw new Error(`psql: ${result.stderr}`);
  return result.stdout.length === 0 ? [] : result.stdout.split("\n");
}

/** True once Postgres is accepting connections. */
export async function isReachable(target: PostgresTarget): Promise<boolean> {
  try {
    await queryRows(target, "select 1");
    return true;
  } catch {
    return false;
  }
}

/**
 * Wait for Postgres to accept connections, or give up after [timeoutMs].
 *
 * Returns rather than throws, so each caller decides what a database that
 * never came up means: setup stops, while the console's own start logs it and
 * carries on serving the dashboard.
 */
export async function waitUntilReachable(
  target: PostgresTarget,
  timeoutMs = 120_000,
  pollMs = 2000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isReachable(target)) return true;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return false;
}

/** A SQL string literal, quoted and escaped. */
export function literal(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}
