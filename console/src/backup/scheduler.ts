/**
 * Starting scheduled backups, and changing their schedule.
 *
 * A check once a minute rather than a timer set for the next slot: the
 * schedule can change in `.env` at any moment, a timer set days ahead drifts
 * across a suspended laptop, and a check that finds nothing to do costs one
 * directory listing.
 */
import { readEnvFile, updateSettings } from "../env_file.ts";
import { type BackupOutcome, backupStatus, startBackup } from "./create.ts";
import { listBackups } from "./files.ts";
import {
  type Frequency,
  isDue,
  MAX_KEEP,
  nextSlot,
  parseSchedule,
  type Schedule,
  scheduleSettings,
} from "./schedule.ts";

const CHECK_MS = 60 * 1000;

/**
 * The first check waits this long after the console starts, so it does not
 * find the database still coming up and spend its attempt on that.
 */
const FIRST_CHECK_MS = 5 * 60 * 1000;

let lastAttempt: Date | null = null;

/** Check for a due backup every minute, from a few minutes after start. */
export function startScheduler(projectDir: string, isConfigured: () => boolean): void {
  const check = () =>
    startIfDue(projectDir, isConfigured, new Date()).catch((error) =>
      console.error("[backup] scheduled check:", error)
    );
  setTimeout(() => {
    void check();
    setInterval(check, CHECK_MS);
  }, FIRST_CHECK_MS);
}

async function startIfDue(
  projectDir: string,
  isConfigured: () => boolean,
  now: Date,
): Promise<void> {
  if (!isConfigured() || backupStatus().running !== null) return;
  const { schedule } = parseSchedule(readEnvFile(projectDir));
  if (schedule === null) return;
  const newest = (await listBackups(projectDir))[0];
  if (!isDue(now, schedule, newest ? new Date(newest.createdAt) : null, lastAttempt)) {
    return;
  }

  lastAttempt = now;
  console.log("[backup] starting a scheduled backup");
  startBackup(projectDir, schedule.passphrase ?? "", true);
}

/** What the dashboard shows about the schedule. */
export interface ScheduleStatus {
  keep: number;
  every: Frequency;
  hour: number;
  weekday: number;
  encrypted: boolean;
  /** Why `.env` cannot be read as a schedule, when it cannot. */
  problem: string | null;
  /** When the next scheduled backup starts, or null when there is none. */
  next: string | null;
  /**
   * Whether one is overdue — missed while the server was off, or never made
   * yet — and starts at the next check rather than at [next].
   */
  dueNow: boolean;
  lastScheduled: BackupOutcome | null;
}

export async function scheduleStatus(
  projectDir: string,
  now = new Date(),
): Promise<ScheduleStatus> {
  const { schedule, problem } = parseSchedule(readEnvFile(projectDir));
  const { running, lastScheduled } = backupStatus();
  if (schedule === null) {
    return {
      keep: 0,
      every: "daily",
      hour: 0,
      weekday: 0,
      encrypted: false,
      problem,
      next: null,
      dueNow: false,
      lastScheduled,
    };
  }
  const newest = (await listBackups(projectDir))[0];
  return {
    keep: schedule.keep,
    every: schedule.every,
    hour: schedule.hour,
    weekday: schedule.weekday,
    encrypted: schedule.passphrase !== undefined,
    problem: null,
    next: schedule.keep > 0 ? nextSlot(now, schedule).toISOString() : null,
    dueNow: running === null &&
      isDue(now, schedule, newest ? new Date(newest.createdAt) : null, lastAttempt),
    lastScheduled,
  };
}

/** A schedule as the dashboard sends it. */
export interface ScheduleRequest {
  keep: unknown;
  every: unknown;
  hour: unknown;
  weekday: unknown;
  /** Whether scheduled backups are encrypted. */
  encrypt: unknown;
  /** A new passphrase, or empty to keep the one already set. */
  passphrase: unknown;
}

/**
 * Check [request] and write it to `.env`. Returns a message saying what is
 * wrong with it, or null once it is saved.
 */
export async function saveSchedule(
  projectDir: string,
  request: ScheduleRequest,
): Promise<string | null> {
  const whole = (value: unknown, max: number) =>
    typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= max
      ? value
      : null;
  const keep = whole(request.keep, MAX_KEEP);
  const hour = whole(request.hour, 23);
  const weekday = whole(request.weekday, 6);
  if (keep === null) {
    return `Backups to keep must be a whole number from 0 to ${MAX_KEEP}.`;
  }
  if (request.every !== "daily" && request.every !== "weekly") {
    return "How often must be every day or every week.";
  }
  if (hour === null) return "Pick the hour a backup starts.";
  if (weekday === null) return "Pick the day a weekly backup starts.";

  const typed = typeof request.passphrase === "string" ? request.passphrase : "";
  const current = parseSchedule(readEnvFile(projectDir)).schedule?.passphrase;
  let passphrase: string | undefined;
  if (request.encrypt === true) {
    passphrase = typed || current;
    if (!passphrase) return "Type a passphrase to encrypt scheduled backups with.";
  }

  const schedule: Schedule = { keep, every: request.every, hour, weekday, passphrase };
  await updateSettings(scheduleSettings(schedule), projectDir);
  return null;
}
