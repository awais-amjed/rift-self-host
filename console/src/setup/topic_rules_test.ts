import { assert, assertEquals } from "jsr:@std/assert@1";

import { TOPIC_RULE_NAMES, TOPIC_RULES_SQL, TOPIC_RULES_VERSION } from "./topic_rules.ts";

/**
 * The shape of the join rules, which the database suite cannot see: they sit
 * on Realtime's own table, which the test database does not have.
 *
 * Unwrapped, the check reads like it runs once — it never mentions the row —
 * and it still runs once per daily partition, so a join slows as the server
 * ages and nothing at install time shows it. That is the edit these guard
 * against.
 */

Deno.test("every topic check is asked once, in a subquery", () => {
  const calls = TOPIC_RULES_SQL.match(/[^\n]*app\.can_use_topic\(/g) ?? [];
  assertEquals(calls.length, TOPIC_RULE_NAMES.length);
  for (const line of calls) {
    assert(
      /(USING|WITH CHECK) \(\(SELECT app\.can_use_topic\($/.test(line.trim()),
      `not wrapped in (SELECT …): ${line.trim()}`,
    );
  }
});

Deno.test("each rule is made, and marked with the current version", () => {
  for (const name of TOPIC_RULE_NAMES) {
    assert(TOPIC_RULES_SQL.includes(`CREATE POLICY ${name} ON realtime.messages`));
    assert(
      TOPIC_RULES_SQL.includes(
        `COMMENT ON POLICY ${name} ON realtime.messages IS '${TOPIC_RULES_VERSION}'`,
      ),
      `${name} is not marked, so servers with an older shape keep it`,
    );
  }
});
