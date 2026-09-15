import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  DEFAULT_SCHEDULE,
  isDue,
  lastSlot,
  nextSlot,
  parseSchedule,
  RETRY_MS,
  type Schedule,
  scheduleSettings,
} from "./schedule.ts";

const at = (iso: string) => new Date(iso);
const daily: Schedule = { ...DEFAULT_SCHEDULE, hour: 3 };
// 2026-09-15 is a Tuesday.
const weekly: Schedule = { ...DEFAULT_SCHEDULE, every: "weekly", hour: 3, weekday: 0 };

Deno.test("a stack that never set a schedule backs up daily and keeps five", () => {
  assertEquals(parseSchedule({}), { schedule: DEFAULT_SCHEDULE, problem: null });
});

Deno.test("an unreadable setting stops the schedule instead of using the default", () => {
  // BACKUP_KEEP=fifty read as 5 would delete backups the operator meant to keep.
  for (
    const env of <Record<string, string>[]> [
      { BACKUP_KEEP: "fifty" },
      { BACKUP_KEEP: "-1" },
      { BACKUP_KEEP: "2.5" },
      { BACKUP_HOUR: "24" },
      { BACKUP_WEEKDAY: "7" },
      { BACKUP_EVERY: "hourly" },
      { BACKUP_PASSPHRASE_BASE64: "not base64!" },
    ]
  ) {
    const { schedule, problem } = parseSchedule(env);
    assertEquals(schedule, null, JSON.stringify(env));
    assert(problem?.includes("Nothing is scheduled or deleted"));
  }
});

Deno.test("a schedule survives being written to .env and read back", () => {
  const schedule: Schedule = {
    keep: 0,
    every: "weekly",
    hour: 23,
    weekday: 6,
    passphrase: "p#ss ${word} 'quoted' ünïcode",
  };
  const written = scheduleSettings(schedule);
  assert(!written.BACKUP_PASSPHRASE_BASE64.includes("$"), "a $ would break compose");
  assertEquals(parseSchedule(written), { schedule, problem: null });
  assertEquals(
    parseSchedule(scheduleSettings({ ...schedule, passphrase: undefined })).schedule
      ?.passphrase,
    undefined,
  );
});

Deno.test("daily slots fall at the hour, today or yesterday", () => {
  assertEquals(lastSlot(at("2026-09-15T12:00:00Z"), daily), at("2026-09-15T03:00:00Z"));
  assertEquals(lastSlot(at("2026-09-15T02:59:00Z"), daily), at("2026-09-14T03:00:00Z"));
  assertEquals(lastSlot(at("2026-09-15T03:00:00Z"), daily), at("2026-09-15T03:00:00Z"));
  assertEquals(nextSlot(at("2026-09-15T03:00:00Z"), daily), at("2026-09-16T03:00:00Z"));
  // Across a month end.
  assertEquals(nextSlot(at("2026-09-30T12:00:00Z"), daily), at("2026-10-01T03:00:00Z"));
});

Deno.test("weekly slots fall on the day, this week or last", () => {
  assertEquals(lastSlot(at("2026-09-15T12:00:00Z"), weekly), at("2026-09-13T03:00:00Z"));
  assertEquals(lastSlot(at("2026-09-13T02:00:00Z"), weekly), at("2026-09-06T03:00:00Z"));
  assertEquals(lastSlot(at("2026-09-13T03:30:00Z"), weekly), at("2026-09-13T03:00:00Z"));
  assertEquals(nextSlot(at("2026-09-15T12:00:00Z"), weekly), at("2026-09-20T03:00:00Z"));
  const tuesday = { ...weekly, weekday: 2 };
  assertEquals(lastSlot(at("2026-09-15T12:00:00Z"), tuesday), at("2026-09-15T03:00:00Z"));
});

Deno.test("a backup is due once per slot, and never when keeping zero", () => {
  const now = at("2026-09-15T03:01:00Z");
  assert(isDue(now, daily, null, null), "nothing made yet");
  assert(
    isDue(now, daily, at("2026-09-14T03:00:00Z"), null),
    "yesterday's is older than today's slot",
  );
  assert(!isDue(now, daily, at("2026-09-15T03:00:00Z"), null), "today's already started");
  assert(!isDue(now, { ...daily, keep: 0 }, null, null), "zero turns it off");
  // Missed while the machine was off: due as soon as the console is back.
  assert(isDue(at("2026-09-15T18:00:00Z"), daily, at("2026-09-14T03:00:00Z"), null));
});

Deno.test("a failed scheduled backup waits an hour before trying again", () => {
  const failedAt = at("2026-09-15T03:01:00Z");
  const yesterday = at("2026-09-14T03:00:00Z");
  assert(!isDue(new Date(failedAt.getTime() + RETRY_MS - 1), daily, yesterday, failedAt));
  assert(isDue(new Date(failedAt.getTime() + RETRY_MS), daily, yesterday, failedAt));
});
