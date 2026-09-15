/**
 * When scheduled backups run and how many backups are kept.
 *
 * Held in `.env` beside everything else the operator can set, so a restored
 * server keeps its schedule, and read on every check, so a change takes effect
 * without a restart. Nothing here touches the disk; scheduler.ts does.
 */
import { decodeBase64, encodeBase64 } from "jsr:@std/encoding@1/base64";

export type Frequency = "daily" | "weekly";

export interface Schedule {
  /** How many backups to keep. Zero turns scheduled backups off. */
  keep: number;
  every: Frequency;
  /** The UTC hour a backup starts, 0–23. */
  hour: number;
  /** For weekly backups, the UTC day: 0 is Sunday. */
  weekday: number;
  passphrase: string | undefined;
}

/** The `.env` names, one per [Schedule] field. */
export const SCHEDULE_SETTINGS = {
  keep: "BACKUP_KEEP",
  every: "BACKUP_EVERY",
  hour: "BACKUP_HOUR",
  weekday: "BACKUP_WEEKDAY",
  // Base64, because a passphrase may hold `$`, `#` or quotes, and compose
  // parses the whole of `.env` — one unbalanced `${` in it breaks every
  // `docker compose` command on the machine.
  passphrase: "BACKUP_PASSPHRASE_BASE64",
} as const;

export const DEFAULT_SCHEDULE: Schedule = {
  keep: 5,
  every: "daily",
  hour: 3,
  weekday: 0,
  passphrase: undefined,
};

export const MAX_KEEP = 1000;

/**
 * Wait this long before trying a failed scheduled backup again. Long enough
 * not to fill the log while the database is down, short enough that a backup
 * missed during an update still happens the same day.
 */
export const RETRY_MS = 60 * 60 * 1000;

/**
 * The schedule `.env` describes, or the reason it cannot be read.
 *
 * A value that is present but unreadable is refused, not replaced by its
 * default: `BACKUP_KEEP=fifty` quietly read as 5 would delete forty-five
 * backups the operator meant to keep.
 */
export function parseSchedule(
  env: Record<string, string>,
): { schedule: Schedule; problem: null } | { schedule: null; problem: string } {
  const read = (key: keyof typeof SCHEDULE_SETTINGS) => {
    const value = env[SCHEDULE_SETTINGS[key]];
    return value === undefined || value.trim() === "" ? undefined : value.trim();
  };
  const whole = (key: "keep" | "hour" | "weekday", max: number) => {
    const value = read(key);
    if (value === undefined) return DEFAULT_SCHEDULE[key];
    const number = /^\d+$/.test(value) ? Number(value) : NaN;
    return number <= max ? number : NaN;
  };

  const keep = whole("keep", MAX_KEEP);
  const hour = whole("hour", 23);
  const weekday = whole("weekday", 6);
  const every = read("every") ?? DEFAULT_SCHEDULE.every;
  const encoded = read("passphrase");
  const passphrase = encoded === undefined ? undefined : decodePassphrase(encoded);

  const problems = [
    Number.isNaN(keep) &&
    `${SCHEDULE_SETTINGS.keep} must be a whole number from 0 to ${MAX_KEEP}`,
    Number.isNaN(hour) && `${SCHEDULE_SETTINGS.hour} must be a whole number from 0 to 23`,
    Number.isNaN(weekday) &&
    `${SCHEDULE_SETTINGS.weekday} must be a whole number from 0 to 6`,
    every !== "daily" && every !== "weekly" &&
    `${SCHEDULE_SETTINGS.every} must be daily or weekly`,
    passphrase === null && `${SCHEDULE_SETTINGS.passphrase} is not valid base64`,
  ].filter((problem): problem is string => typeof problem === "string");
  if (problems.length > 0) {
    return {
      schedule: null,
      problem: `${problems.join(". ")}. Nothing is scheduled or deleted.`,
    };
  }

  return {
    schedule: {
      keep,
      every: every as Frequency,
      hour,
      weekday,
      passphrase: passphrase || undefined,
    },
    problem: null,
  };
}

/** The `.env` lines for [schedule]. */
export function scheduleSettings(schedule: Schedule): Record<string, string> {
  return {
    [SCHEDULE_SETTINGS.keep]: String(schedule.keep),
    [SCHEDULE_SETTINGS.every]: schedule.every,
    [SCHEDULE_SETTINGS.hour]: String(schedule.hour),
    [SCHEDULE_SETTINGS.weekday]: String(schedule.weekday),
    [SCHEDULE_SETTINGS.passphrase]: schedule.passphrase
      ? encodeBase64(new TextEncoder().encode(schedule.passphrase))
      : "",
  };
}

function decodePassphrase(encoded: string): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64(encoded));
  } catch {
    return null;
  }
}

/** The most recent moment a backup was due, at or before [now]. */
export function lastSlot(now: Date, schedule: Schedule): Date {
  const slot = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
    schedule.hour,
  ));
  if (schedule.every === "daily") {
    if (slot > now) slot.setUTCDate(slot.getUTCDate() - 1);
    return slot;
  }
  slot.setUTCDate(slot.getUTCDate() - ((slot.getUTCDay() - schedule.weekday + 7) % 7));
  if (slot > now) slot.setUTCDate(slot.getUTCDate() - 7);
  return slot;
}

/** The next moment a backup is due, after [now]. */
export function nextSlot(now: Date, schedule: Schedule): Date {
  const slot = lastSlot(now, schedule);
  slot.setUTCDate(slot.getUTCDate() + (schedule.every === "daily" ? 1 : 7));
  return slot;
}

/**
 * Whether a scheduled backup should start now.
 *
 * Due when no backup has started since the last slot, which also covers a
 * slot missed while the machine or the console was down: it runs when the
 * console is back. Any backup counts, one made by hand included — two in the
 * same hour are not worth one more slot of the ones kept. A failed attempt
 * waits [RETRY_MS] before the next.
 */
export function isDue(
  now: Date,
  schedule: Schedule,
  newestBackup: Date | null,
  lastAttempt: Date | null,
): boolean {
  if (schedule.keep <= 0) return false;
  const slot = lastSlot(now, schedule);
  if (newestBackup !== null && newestBackup >= slot) return false;
  if (
    lastAttempt !== null && lastAttempt >= slot &&
    now.getTime() - lastAttempt.getTime() < RETRY_MS
  ) return false;
  return true;
}
