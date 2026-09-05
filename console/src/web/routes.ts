/**
 * What the console answers.
 *
 * Nine routes. Everything but `/login` needs a session, and the check is at
 * the top of [handle] rather than per-route so a route added later cannot
 * forget it.
 */
import { announce } from "../banner.ts";
import { setting } from "../env_file.ts";
import { runChecks } from "../health.ts";
import { restartService, serviceStatuses, startStack } from "../docker.ts";
import { targetFromEnv } from "../postgres.ts";
import { defaultPaths, runSetup, type SetupProgress } from "../setup/run.ts";
import {
  closeSession,
  configuredPassword,
  isAuthenticated,
  openSession,
  passwordMatches,
  sessionCookie,
  tokenFrom,
} from "./auth.ts";
import { dashboardPage, loginPage, setupPage } from "./page.ts";

/** True once setup has written the environment file. */
export async function isConfigured(projectDir: string): Promise<boolean> {
  try {
    await Deno.stat(`${projectDir}/.env`);
    return true;
  } catch {
    return false;
  }
}

function html(body: string, headers: HeadersInit = {}): Response {
  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8", ...headers },
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function redirect(to: string, headers: HeadersInit = {}): Response {
  return new Response(null, { status: 303, headers: { Location: to, ...headers } });
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

  // Before setup there is no password to check, because the file that would
  // hold one has not been written. The console is loopback-bound, and the
  // window closes the moment setup finishes.
  const needsPassword = configuredPassword() !== null;
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
    return await isConfigured(paths.projectDir)
      ? html(dashboardPage(setting("RIFT_DOMAIN") ?? "Your server"))
      : html(setupPage());
  }

  if (path === "/api/setup" && request.method === "POST") {
    return setupStream(await request.json());
  }

  if (path === "/api/status") {
    const target = targetFromEnv();
    const [services, checks] = await Promise.all([
      serviceStatuses(),
      runChecks(target, paths.migrationsDir).catch(() => []),
    ]);
    return json({ services, checks, secrets: visibleSecrets() });
  }

  if (path === "/api/restart" && request.method === "POST") {
    const result = await startStack(["full"]);
    return json({ ok: result.ok, error: result.ok ? undefined : result.stderr });
  }

  if (path === "/api/restart-service" && request.method === "POST") {
    const { service } = await request.json();
    const result = await restartService(String(service));
    return json({ ok: result.ok, error: result.ok ? undefined : result.stderr });
  }

  return new Response("Not found", { status: 404 });
}

/**
 * What the dashboard is allowed to show.
 *
 * The service-role key is deliberately absent. Nothing an operator does by
 * hand needs it any more — the console makes the one call that did — and a
 * value on a page is a value in a screenshot.
 */
function visibleSecrets(): { name: string; value: string }[] {
  const entries: [string, string | undefined][] = [
    ["Server URL", `https://${setting("RIFT_DOMAIN") ?? ""}`],
    // The publishable key, because that is what the server actually issues to
    // clients. Showing the legacy JWT beside it would invite somebody to paste
    // the one nothing hands out any more.
    ["Publishable key", setting("SUPABASE_PUBLISHABLE_KEY")],
    ["LiveKit URL", `wss://${setting("RIFT_DOMAIN") ?? ""}`],
  ];
  return entries
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .map(([name, value]) => ({ name, value }));
}

/**
 * Run setup, streaming one JSON object per line as each step lands.
 *
 * Newline-delimited JSON rather than server-sent events: the page needs no
 * reconnection and no event types, and a plain stream is one `getReader()`
 * loop on the other end. Pulling images can take minutes, and a request that
 * returns nothing for that long reads as a hang.
 */
function setupStream(request: {
  domain: string;
  serverName: string;
}): Response {
  const encoder = new TextEncoder();

  const body = new ReadableStream({
    async start(controller) {
      const send = (value: unknown) =>
        controller.enqueue(encoder.encode(JSON.stringify(value) + "\n"));

      try {
        const result = await runSetup(
          {
            domain: request.domain,
            serverName: request.serverName || "Rift",
          },
          targetFromEnv(),
          defaultPaths(),
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
      } catch (error) {
        send({ error: error instanceof Error ? error.message : String(error) });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(body, {
    headers: {
      "Content-Type": "application/x-ndjson",
      "Cache-Control": "no-store",
      // Nothing buffers this today, but a reverse proxy in front of the console
      // would, and the stream is the only feedback during setup.
      "X-Accel-Buffering": "no",
    },
  });
}
