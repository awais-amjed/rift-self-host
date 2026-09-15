/** The Backups tab's endpoints: making, listing, scheduling and fetching backups. */
import { backupStatus, startBackup } from "../../backup/create.ts";
import { deleteBackup, listBackups, openBackup } from "../../backup/files.ts";
import { saveSchedule, scheduleStatus } from "../../backup/scheduler.ts";
import { type ApiRoutes, failure, json } from "../responses.ts";
import { isConfigured } from "../stack_state.ts";

export const backupRoutes: ApiRoutes = async (request, url, paths) => {
  const path = url.pathname;

  if (path === "/api/backups") {
    return json({
      files: await listBackups(paths.projectDir),
      schedule: await scheduleStatus(paths.projectDir),
      ...backupStatus(),
    });
  }

  if (path === "/api/backups/schedule" && request.method === "POST") {
    if (!isConfigured()) {
      return json({ error: "Set the server up before scheduling backups." }, 409);
    }
    const problem = await saveSchedule(paths.projectDir, await request.json());
    if (problem !== null) return json({ error: problem }, 400);
    return json({ schedule: await scheduleStatus(paths.projectDir) });
  }

  if (path === "/api/backups/delete" && request.method === "POST") {
    const { name } = await request.json();
    if (!await deleteBackup(paths.projectDir, String(name ?? ""))) {
      return json({
        error: "There is no backup by that name. It may already be deleted.",
      }, 404);
    }
    return json({ deleted: name });
  }

  if (path === "/api/backups/download") {
    const name = url.searchParams.get("name") ?? "";
    const opened = await openBackup(paths.projectDir, name);
    if (!opened) return json({ error: "There is no backup by that name." }, 404);
    // Streamed from disk: a backup with many attachments is larger than the
    // console should ever hold in memory.
    return new Response(opened.file.readable, {
      headers: {
        "Content-Type": "application/gzip",
        "Content-Length": String(opened.bytes),
        "Content-Disposition": `attachment; filename="${name}"`,
        "Cache-Control": "no-store",
      },
    });
  }

  if (path === "/api/backup" && request.method === "POST") {
    if (!isConfigured()) {
      return json({ error: "Set the server up before backing it up." }, 409);
    }
    const { passphrase } = await request.json();
    try {
      startBackup(paths.projectDir, String(passphrase ?? ""));
      return json({ started: true }, 202);
    } catch (error) {
      return failure("backup", error);
    }
  }

  return null;
};
