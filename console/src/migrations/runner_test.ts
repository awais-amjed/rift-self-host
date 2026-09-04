import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { applyPlan, checksum, type Migration, readMigrations } from "./runner.ts";
import type { PostgresTarget } from "../postgres.ts";

/** A target no test may actually reach — every test here stops before SQL. */
const unreachable: PostgresTarget = {
  host: "test.invalid",
  port: 1,
  user: "nobody",
  password: "",
  database: "none",
};

function migration(name: string, sql = "select 1;"): Migration {
  return { name, path: `/tmp/${name}`, sql, checksum: "deadbeef" };
}

/** Write [names] as .sql files into a fresh directory and return its path. */
async function directoryOf(names: string[]): Promise<string> {
  const directory = await Deno.makeTempDir({ prefix: "rift-migrations-" });
  for (const name of names) {
    await Deno.writeTextFile(`${directory}/${name}`, `-- ${name}\nselect 1;\n`);
  }
  return directory;
}

Deno.test("migrations run in zero-padded filename order", async () => {
  // The order is the whole contract: 002 grants on tables 001 creates. A sort
  // that put 10 before 2 would fail on a fresh database and nowhere else.
  const directory = await directoryOf([
    "010_push.sql",
    "002_security.sql",
    "001_schema.sql",
    "009_dm_limits.sql",
  ]);

  const found = await readMigrations(directory);
  assertEquals(found.map((m) => m.name), [
    "001_schema.sql",
    "002_security.sql",
    "009_dm_limits.sql",
    "010_push.sql",
  ]);

  await Deno.remove(directory, { recursive: true });
});

Deno.test("only .sql files are migrations", async () => {
  const directory = await directoryOf(["001_schema.sql", "README.md", "notes.txt"]);
  const found = await readMigrations(directory);
  assertEquals(found.map((m) => m.name), ["001_schema.sql"]);
  await Deno.remove(directory, { recursive: true });
});

Deno.test("a checksum follows the bytes, not the filename", async () => {
  const original = await checksum("create table a ();");
  assertEquals(await checksum("create table a ();"), original);

  // A comment is still a change. Anything looser and an edit to a migration's
  // prose would be indistinguishable from an edit to its statements.
  const commented = await checksum("-- why\ncreate table a ();");
  assertEquals(commented === original, false);
});

Deno.test("drift stops the run before any SQL is sent", async () => {
  const plan = {
    applied: [],
    pending: [migration("041_new.sql")],
    drifted: [migration("040_reaction_tallies.sql")],
  };

  // If this reached Postgres it would fail on the connection instead, so the
  // message is the assertion: the run is refused for the right reason.
  const error = await assertRejects(() => applyPlan(unreachable, plan));
  assertStringIncludes(
    error instanceof Error ? error.message : String(error),
    "040_reaction_tallies.sql",
  );
});

Deno.test("nothing pending means nothing runs, even unreachable", async () => {
  const outcomes = await applyPlan(unreachable, {
    applied: [migration("001_schema.sql")],
    pending: [],
    drifted: [],
  });
  assertEquals(outcomes, []);
});
