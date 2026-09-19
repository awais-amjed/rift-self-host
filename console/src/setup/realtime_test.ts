import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";

import { DEFAULT_LIMITS, TENANT, updateStatement } from "./realtime.ts";

/**
 * The limits that decide how big a server can get.
 *
 * These are not tuning knobs with a comfortable margin either side. Both of
 * them fail by discarding work in silence — an over-limit delivery is dropped
 * with nothing in any log, and an over-limit connection is refused with no
 * reason given — so a number that drifts back down is a server that quietly
 * stops working for the people on it. What follows are the relationships that
 * have to hold, not the values, so raising a limit on purpose does not break
 * the suite but halving one by accident does.
 */

Deno.test("every limit reaches the tenant row", () => {
  const sql = updateStatement(DEFAULT_LIMITS);
  assertMatch(sql, new RegExp(`WHERE external_id = '${TENANT}'`));
  for (
    const [column, value] of [
      ["max_events_per_second", DEFAULT_LIMITS.maxEventsPerSecond],
      ["max_bytes_per_second", DEFAULT_LIMITS.maxBytesPerSecond],
      ["max_presence_events_per_second", DEFAULT_LIMITS.maxPresenceEventsPerSecond],
      ["max_concurrent_users", DEFAULT_LIMITS.maxConcurrentUsers],
      ["max_joins_per_second", DEFAULT_LIMITS.maxJoinsPerSecond],
    ] as const
  ) {
    assertMatch(sql, new RegExp(`${column}\\s+= ${value}`));
  }
});

Deno.test("there are enough events for everybody online to hear each other", () => {
  // An event is a *delivery*, so one message in an open channel costs one
  // event per person online. The budget therefore has to be the connection
  // count multiplied by a believable message rate, or a full server goes
  // quiet at its busiest moment — which is exactly what the old pair of
  // numbers did: 5,000 events against 1,000 users is five messages a second
  // for the whole server.
  const messagesPerSecond = DEFAULT_LIMITS.maxEventsPerSecond /
    DEFAULT_LIMITS.maxConcurrentUsers;
  assert(
    messagesPerSecond >= 10,
    `a full server gets ${messagesPerSecond} messages a second before ` +
      "Realtime starts dropping them without a word",
  );
});

Deno.test("everybody can come back at once after a restart", () => {
  // A restart reconnects the whole server at the same moment. If joining is
  // rate-limited far below the connection count, coming back up is a
  // thundering herd against its own limiter.
  assert(
    DEFAULT_LIMITS.maxJoinsPerSecond * 10 >= DEFAULT_LIMITS.maxConcurrentUsers,
    "a full server would take more than ten seconds of joins to reconnect",
  );
});

Deno.test("the connection ceiling and the file-descriptor ceiling agree", async () => {
  // Every WebSocket is a file descriptor, so `RLIMIT_NOFILE` is a second,
  // invisible ceiling on `max_concurrent_users`. They were 10,000 and 1,000,
  // and raising only the tenant row moved the failure rather than removing
  // it: joins started coming back as `{:error, :emfile}` instead.
  const compose = await Deno.readTextFile(
    new URL("../../../docker-compose.yml", import.meta.url),
  );
  const service = compose.split("\n  realtime:\n")[1]
    .split(/\n {2}[a-z][a-z0-9-]*:\n/)[0];
  const limit = Number(service.match(/^\s+RLIMIT_NOFILE: "(\d+)"$/m)?.[1]);

  assertEquals(Number.isFinite(limit), true, "RLIMIT_NOFILE is not set on realtime");
  assert(
    limit >= DEFAULT_LIMITS.maxConcurrentUsers * 2,
    `RLIMIT_NOFILE is ${limit}, which leaves no room for ` +
      `${DEFAULT_LIMITS.maxConcurrentUsers} sockets plus the database pool`,
  );
});
