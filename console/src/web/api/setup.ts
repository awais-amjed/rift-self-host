/**
 * The endpoints before a stack exists: setting one up from scratch, or
 * restoring one from an encrypted backup.
 */
import { announce } from "../../banner.ts";
import { targetFromEnv } from "../../postgres.ts";
import { optionsFromEnv } from "../../setup/options.ts";
import { runSetup, type SetupProgress } from "../../setup/run.ts";
import { openSealedBackup, sealedBackupPresent } from "../../backup/restore.ts";
import { prepareStack } from "../../boot.ts";
import { type ApiRoutes, json, progressStream } from "../responses.ts";
import { isConfigured } from "../stack_state.ts";

export const setupRoutes: ApiRoutes = async (request, url, paths) => {
  const path = url.pathname;

  if (path === "/api/setup" && request.method === "POST") {
    // Only the page is gated on `isConfigured`; this is the endpoint behind
    // it. A second run generates a fresh set of everything — a new Postgres
    // password, new signing keys — writes them over `.env`, and then cannot
    // reach the database it has just locked itself out of. There is no
    // recovery worth offering, so it is refused.
    if (isConfigured()) {
      return json({
        error: "This stack is already set up. Setup generates a new database " +
          "password and new signing keys, which would lock the stack out of " +
          "its own database.",
      }, 409);
    }
    const options = await request.json();
    return progressStream(async (send) => {
      // Anything the page did not send falls back to the .env-or-default
      // set, so a caller posting only a domain still gets a whole stack.
      const result = await runSetup(
        { ...optionsFromEnv(paths.projectDir), ...options },
        targetFromEnv(),
        paths,
        (progress: SetupProgress) => send(progress),
      );
      // Both channels, because the operator is on the page and the login
      // page sends them to the log. Until this existed the log's last word
      // was the startup banner's "no password yet", printed before setup
      // could possibly have made one.
      announce({ password: result.secrets.consolePassword, configured: true });
      send({
        inviteLink: result.server.inviteLink,
        serverId: result.server.serverId,
        consolePassword: result.secrets.consolePassword,
      });
    });
  }

  if (path === "/api/restore" && request.method === "POST") {
    if (isConfigured()) {
      return json({
        error: "This server is already set up, so there is nothing to restore into.",
      }, 409);
    }
    if (!await sealedBackupPresent(paths.projectDir)) {
      return json(
        { error: "There is no encrypted backup beside the compose file." },
        404,
      );
    }
    const { passphrase } = await request.json();
    // A wrong passphrase fails before anything is written, so the page can
    // simply ask again.
    return progressStream(async (send) => {
      send({ step: "Opening the backup", done: false });
      await openSealedBackup(paths.projectDir, String(passphrase ?? ""));
      send({ step: "Opening the backup", done: true });
      await prepareStack(paths, (step) => send({ step, done: false }));
      send({ restored: true });
    });
  }

  return null;
};
