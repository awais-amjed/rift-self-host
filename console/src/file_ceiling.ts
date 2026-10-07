/**
 * The largest file this machine accepts, kept the same in the four places
 * that have to agree.
 *
 *   1. `.env`, as `RIFT_MAX_FILE_MB`: what the operator chose.
 *   2. The compose override, as storage's `FILE_SIZE_LIMIT`: what is enforced.
 *   3. The storage container, which reads it only when it is created.
 *   4. The database, through `app.set_file_ceiling`: what the app is told,
 *      and what no server's own limit may go above.
 *
 * Before this the second was fixed at 50 MB in the compose file and the
 * fourth did not exist, so a server set to 200 MB in the app accepted the
 * setting and then failed every upload past 50 with a 413.
 */
import { join } from "jsr:@std/path@1";
import { restartService } from "./docker.ts";
import { readEnvFile, updateSetting } from "./env_file.ts";
import { type PostgresTarget, runSql } from "./postgres.ts";
import {
  type CeilingRefresh,
  OVERRIDE_FILE,
  OVERRIDE_MARK,
  refreshFileCeiling,
} from "./setup/config_files.ts";
import { maxFileMbFrom, megabytes, validFileMb } from "./setup/options.ts";

/** What the dashboard shows. */
export interface FileCeiling {
  /** What `.env` says, in MB. */
  mb: number;
  /**
   * Whether the console can set it: false when the operator keeps a compose
   * override of their own, which then holds storage's limit.
   */
  managed: boolean;
}

/** Record [bytes] as the ceiling, lowering any server set above it. */
export async function recordFileCeiling(
  target: PostgresTarget,
  bytes: number,
): Promise<void> {
  const result = await runSql(target, `SELECT app.set_file_ceiling(${bytes});`);
  if (!result.ok) throw new Error(result.error);
}

/** Whether the compose override is one the operator wrote themselves. */
async function overrideIsTheirs(projectDir: string): Promise<boolean> {
  const text = await Deno.readTextFile(join(projectDir, OVERRIDE_FILE)).catch(() => null);
  return text !== null && !text.startsWith(OVERRIDE_MARK);
}

/** The ceiling as the dashboard shows it. */
export async function readFileCeiling(projectDir: string): Promise<FileCeiling> {
  return {
    mb: maxFileMbFrom(readEnvFile(projectDir)),
    managed: !await overrideIsTheirs(projectDir),
  };
}

/**
 * Bring the override and storage up to `.env` when the console starts.
 *
 * Returns what the refresh did, so the caller can recreate storage when it
 * was "written" and the stack is already running. Recording in the database
 * is [recordFileCeiling]'s, after the schema that holds it is in place.
 */
export function refreshAtBoot(projectDir: string): Promise<CeilingRefresh> {
  return refreshFileCeiling(
    projectDir,
    megabytes(maxFileMbFrom(readEnvFile(projectDir))),
  );
}

/**
 * Change the ceiling to [mb] from the dashboard.
 *
 * Storage is recreated before the database hears of it, so the app is never
 * told of a limit storage does not yet enforce. Lowering it brings down every
 * server set above it.
 */
export async function changeFileCeiling(
  target: PostgresTarget,
  projectDir: string,
  mb: number,
): Promise<void> {
  if (!validFileMb(mb)) {
    throw new Error("The largest file must be a whole number of MB, at least 1.");
  }
  const bytes = megabytes(mb);
  if (await overrideIsTheirs(projectDir)) {
    throw new Error(
      "docker-compose.override.yml is yours, so the console leaves it alone. " +
        `Set FILE_SIZE_LIMIT under storage there to ${bytes}, then recreate storage.`,
    );
  }
  await updateSetting("RIFT_MAX_FILE_MB", String(mb), projectDir);
  const refreshed = await refreshFileCeiling(projectDir, bytes);
  if (refreshed === "written") {
    const restarted = await restartService("storage");
    if (!restarted.ok) throw new Error(`Storage did not restart: ${restarted.stderr}`);
  }
  await recordFileCeiling(target, bytes);
}
