/**
 * What the console answers.
 *
 * The pages and the session live here; each dashboard area's endpoints live in
 * `api/`. Everything but `/login` needs a session, and the check is at the top
 * of [handle] rather than per-area so an endpoint added later cannot forget it.
 */
import { readEnvFile, setting } from "../env_file.ts";
import { fields, optionsFromEnv } from "../setup/options.ts";
import { defaultPaths } from "../setup/run.ts";
import { sealedBackupPresent } from "../backup/restore.ts";
import {
  HASH_SETTING,
  hashPassword,
  PLAIN_SETTING,
  storedPasswordHash,
  verifyPassword,
} from "../console_password.ts";
import { consolePublishedOn } from "../docker.ts";
import {
  closeSession,
  isAuthenticated,
  openSession,
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
import { fontResponse } from "./fonts.ts";
import { setupRunning } from "./api/setup.ts";
import { type ApiRoutes, html, json, redirect } from "./responses.ts";
import { isConfigured, setupUnfinished, setupWasLocal } from "./stack_state.ts";
import { backupRoutes } from "./api/backups.ts";
import { securityRoutes } from "./api/security.ts";
import { serverRoutes } from "./api/servers.ts";
import { setupRoutes } from "./api/setup.ts";
import { statusRoutes } from "./api/status.ts";
import { updateRoutes } from "./api/update.ts";

const API: ApiRoutes[] = [
  statusRoutes,
  updateRoutes,
  serverRoutes,
  securityRoutes,
  backupRoutes,
  setupRoutes,
];

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/**
 * Whether the console's published port is on the loopback.
 *
 * The check is on the *published* interface rather than what the process binds
 * to, which is always 0.0.0.0 inside the container — what matters is what
 * compose exposed to the host. Docker says what that is ([consolePublishedOn]);
 * `.env` only says what the next recreate will do, and is the fallback when
 * Docker cannot be asked.
 */
async function boundToLoopback(): Promise<boolean> {
  const bind = await consolePublishedOn().catch(() => null) ??
    setting("CONSOLE_BIND") ?? "127.0.0.1";
  return LOOPBACK.has(bind);
}

/**
 * Why a request that changes something is refused before it is looked at, or
 * null. The console answers on the loopback, and a page on any other site the
 * operator has open can still send it requests:
 *
 *  - a form or `text/plain` POST from another origin needs no preflight, so
 *    every POST under /api must say it is JSON, which no page can send cross
 *    origin without the console's say-so;
 *  - a browser names the page a request came from in `Origin`, and one that
 *    is not this console's own is refused;
 *  - before there is a password, a name that resolves to 127.0.0.1 from an
 *    attacker's DNS (rebinding) makes their page same-origin, so until then
 *    only a loopback name is answered at all.
 */
export function requestProblem(request: Request, hasPassword: boolean): string | null {
  const url = new URL(request.url);
  const host = request.headers.get("host") ?? url.host;
  if (!hasPassword) {
    const name = host.replace(/:\d+$/, "").toLowerCase();
    if (!LOOPBACK.has(name)) {
      return "Open the console at http://localhost (through an SSH tunnel on a " +
        "remote machine) until it has a password.";
    }
  }
  if (request.method === "GET" || request.method === "HEAD") return null;

  const origin = request.headers.get("origin");
  if (origin !== null) {
    let from: string | null = null;
    try {
      from = new URL(origin).host;
    } catch {
      from = null;
    }
    if (from !== host) return "That request came from another site.";
  }
  if (request.headers.get("sec-fetch-site") === "cross-site") {
    return "That request came from another site.";
  }
  if (url.pathname.startsWith("/api/")) {
    const type = request.headers.get("content-type") ?? "";
    if (!type.toLowerCase().startsWith("application/json")) {
      return "The console only takes JSON here.";
    }
  }
  return null;
}

/**
 * The password hash to ask for, or null for none.
 *
 * An unfinished setup counts as no password on the loopback: setup writes one
 * in its first step and only shows it in its last, so asking for it in between
 * locks the operator out of their own setup. Off the loopback, it still asks
 * for the one `.env` held when setup started, the exposed page's own remedy;
 * dropping it there turned every request into that page, and a setup that then
 * failed could not be resumed.
 */
async function passwordToAsk(loopback: boolean): Promise<string | null> {
  if (!setupUnfinished()) return await storedPasswordHash();
  if (loopback) return null;
  const values = readEnvFile();
  if (values[HASH_SETTING]) return values[HASH_SETTING];
  const plain = values[PLAIN_SETTING];
  return plain ? await hashOnce(plain) : null;
}

/** A hash of [plain] kept for this process, so sessions opened under it stay valid. */
const hashed = new Map<string, string>();
async function hashOnce(plain: string): Promise<string> {
  const known = hashed.get(plain);
  if (known) return known;
  const hash = await hashPassword(plain);
  hashed.set(plain, hash);
  return hash;
}

/**
 * Sign-in is a 600,000-round PBKDF2, so guesses are spaced out and only a few
 * run at once: on a console moved off the loopback, a loop of attempts was
 * both a guessing machine and a way to keep every core busy.
 */
const MAX_VERIFYING = 2;
const FAILURE_DELAY_MS = 1_000;
let verifying = 0;

/** Route one request. */
export async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const paths = defaultPaths();

  // Liveness, for the container healthcheck. Deliberately before the session
  // check: Docker holds no cookie.
  if (path === "/healthz") return new Response("ok");

  if (path.startsWith("/fonts/")) {
    return await fontResponse(path) ?? new Response("Not found", { status: 404 });
  }

  const loopback = await boundToLoopback();
  const password = await passwordToAsk(loopback);
  if (password === null && !loopback) {
    return html(exposedPage());
  }

  const problem = requestProblem(request, password !== null);
  if (problem !== null) return json({ error: problem }, 403);

  if (path === "/login" && request.method === "POST") {
    if (verifying >= MAX_VERIFYING) {
      return new Response("Too many sign-ins at once. Wait a moment and try again.", {
        status: 429,
      });
    }
    verifying++;
    try {
      const form = await request.formData();
      const attempt = String(form.get("password") ?? "");
      if (password !== null && await verifyPassword(attempt, password)) {
        return redirect("/", { "Set-Cookie": sessionCookie(openSession(password)) });
      }
      await new Promise((resolve) => setTimeout(resolve, FAILURE_DELAY_MS));
    } finally {
      verifying--;
    }
    return html(loginPage(true), { "Set-Cookie": sessionCookie(null) });
  }

  if (password !== null && !isAuthenticated(request, password)) {
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
