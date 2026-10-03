/**
 * What the console answers.
 *
 * The pages and the session live here; each dashboard area's endpoints live in
 * `api/`. Everything but `/login` needs a session, and the check is at the top
 * of [handle] rather than per-area so an endpoint added later cannot forget it.
 */
import { setting } from "../env_file.ts";
import { fields, optionsFromEnv } from "../setup/options.ts";
import { defaultPaths } from "../setup/run.ts";
import { sealedBackupPresent } from "../backup/restore.ts";
import {
  closeSession,
  configuredPassword,
  isAuthenticated,
  openSession,
  passwordMatches,
  sessionCookie,
  tokenFrom,
} from "./auth.ts";
import {
  dashboardPage,
  exposedPage,
  loginPage,
  restorePage,
  setupPage,
  setupRunningPage,
} from "./page.ts";
import { setupRunning } from "./api/setup.ts";
import { type ApiRoutes, html, json, redirect } from "./responses.ts";
import { isConfigured, setupUnfinished, setupWasLocal } from "./stack_state.ts";
import { backupRoutes } from "./api/backups.ts";
import { securityRoutes } from "./api/security.ts";
import { serverRoutes } from "./api/servers.ts";
import { setupRoutes } from "./api/setup.ts";
import { statusRoutes } from "./api/status.ts";

const API: ApiRoutes[] = [
  statusRoutes,
  serverRoutes,
  securityRoutes,
  backupRoutes,
  setupRoutes,
];

/**
 * Whether the console's published port is on the loopback.
 *
 * The check is on the *published* interface rather than what the process binds
 * to, which is always 0.0.0.0 inside the container — what matters is what
 * compose exposed to the host.
 */
function boundToLoopback(): boolean {
  const bind = setting("CONSOLE_BIND") ?? "127.0.0.1";
  return bind === "127.0.0.1" || bind === "localhost" || bind === "::1";
}

/** Route one request. */
export async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const paths = defaultPaths();

  // Liveness, for the container healthcheck. Deliberately before the session
  // check: Docker holds no cookie.
  if (path === "/healthz") return new Response("ok");

  if (path === "/login" && request.method === "POST") {
    const expected = configuredPassword();
    const form = await request.formData();
    const attempt = String(form.get("password") ?? "");

    if (expected !== null && await passwordMatches(attempt, expected)) {
      return redirect("/", { "Set-Cookie": sessionCookie(openSession()) });
    }
    return html(loginPage(true), { "Set-Cookie": sessionCookie(null) });
  }

  // Before setup there is no password, because the file that would hold one
  // has not been written yet. That window is safe only because the console is
  // published on the loopback — an operator who moves it to 0.0.0.0 *before*
  // running setup would be handing the Docker socket to the network, so that
  // combination is refused outright rather than trusted to be deliberate.
  //
  // An unfinished setup counts as no password too: setup writes one in its
  // first step and only shows it in its last, so asking for it in between
  // locks the operator out of their own setup.
  const password = setupUnfinished() ? null : configuredPassword();
  if (password === null && !boundToLoopback()) {
    return html(exposedPage());
  }

  const needsPassword = password !== null;
  if (needsPassword && !isAuthenticated(request)) {
    if (path === "/") return html(loginPage(false));
    return json({ error: "Not signed in" }, 401);
  }

  if (path === "/logout") {
    const token = tokenFrom(request);
    if (token) closeSession(token);
    return redirect("/", { "Set-Cookie": sessionCookie(null) });
  }

  if (path === "/") {
    if (!isConfigured()) {
      if (setupRunning()) return html(setupRunningPage());
      // An encrypted backup extracted here is a server waiting for its
      // passphrase, not one waiting to be set up from scratch.
      if (await sealedBackupPresent(paths.projectDir)) return html(restorePage());
      return html(
        setupPage(fields, optionsFromEnv(paths.projectDir), setupUnfinished()),
      );
    }
    return html(dashboardPage(
      setupWasLocal()
        ? `${setting("RIFT_LOCAL_ADDRESS") ?? ""}:${setting("RIFT_LOCAL_PORT") ?? ""}`
        : setting("RIFT_DOMAIN") ?? "Your server",
      setupWasLocal(),
    ));
  }

  for (const routes of API) {
    const response = await routes(request, url, paths);
    if (response !== null) return response;
  }

  return new Response("Not found", { status: 404 });
}
