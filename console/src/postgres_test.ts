import { assertEquals } from "jsr:@std/assert@1";
import { literal } from "./postgres.ts";

Deno.test("a quote in a value is escaped, not terminated", () => {
  // Migration filenames are ours, but the ledger also records checksums and
  // one day an operator-supplied note. Doubling the quote is the whole rule.
  assertEquals(literal("plain"), "'plain'");
  assertEquals(literal("it's"), "'it''s'");
  assertEquals(
    literal("'; DROP TABLE rift_migrations; --"),
    "'''; DROP TABLE rift_migrations; --'",
  );
});

Deno.test("an empty value is still a literal", () => {
  assertEquals(literal(""), "''");
});
