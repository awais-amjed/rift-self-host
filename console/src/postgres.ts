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
 * `POSTGRES_HOST` defaults to the service name rather than `localhost`,
 * because inside a container `localhost` is the container.
 */
export function targetFromEnv(): PostgresTarget {
  return {
    host: Deno.env.get("POSTGRES_HOST") ?? "db",
    port: Number(Deno.env.get("POSTGRES_PORT") ?? "5432"),
    user: Deno.env.get("POSTGRES_USER") ?? "postgres",
    password: Deno.env.get("POSTGRES_PASSWORD") ?? "",
    database: Deno.env.get("POSTGRES_DB") ?? "postgres",
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

  const command = new Deno.Command("psql", {
    args,
    env,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });

  const process = command.spawn();
  const writer = process.stdin.getWriter();
  await writer.write(new TextEncoder().encode(sql));
  await writer.close();

  const { code, stdout, stderr } = await process.output();
  const decoder = new TextDecoder();
  return {
    ok: code === 0,
    output: decoder.decode(stdout).trim(),
    error: decoder.decode(stderr).trim(),
  };
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

  const command = new Deno.Command("psql", {
    args,
    env,
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = await command.output();
  if (code !== 0) {
    throw new Error(`psql: ${new TextDecoder().decode(stderr).trim()}`);
  }

  const text = new TextDecoder().decode(stdout).trim();
  return text.length === 0 ? [] : text.split("\n");
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

/** A SQL string literal, quoted and escaped. */
export function literal(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}
