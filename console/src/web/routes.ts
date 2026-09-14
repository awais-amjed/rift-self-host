/**
 * What the console answers.
 *
 * Ten routes. Everything but `/login` needs a session, and the check is at
 * the top of [handle] rather than per-route so a route added later cannot
 * forget it.
 */
import { announce } from "../banner.ts";
import { setting } from "../env_file.ts";
import { runChecks } from "../health.ts";
import { applyUpgrade, pendingWork } from "../upgrade.ts";
import {
  createServer,
  inviteLinkFor,
  listInvites,
  listServers,
  livekitUrl,
  mintInvite,
  publicUrl,
} from "../servers.ts";
import {
  DEFAULT_API_PORT,
  type LocalTesting,
  readLocalTesting,
  turnOff,
  turnOn,
} from "../local_testing.ts";
import { proxyRoutes } from "../proxy.ts";
import { isRotationKind, lastRotated, rotate } from "../rotation.ts";
import { restartService, restartStack, servicesIn, serviceStatuses } from "../docker.ts";
import { targetFromEnv } from "../postgres.ts";
import { fields, optionsFromEnv, type SetupOptions } from "../setup/options.ts";
import { defaultPaths, type Paths, runSetup, type SetupProgress } from "../setup/run.ts";
import {
  closeSession,
  configuredPassword,
  isAuthenticated,
  openSession,
  passwordMatches,
  sessionCookie,
  tokenFrom,
} from "./auth.ts";
import { dashboardPage, exposedPage, loginPage, restorePage, setupPage } from "./page.ts";
import { backupStatus, listBackups, startBackup } from "../backup/create.ts";
import { openSealedBackup, sealedBackupPresent } from "../backup/restore.ts";
import { prepareStack } from "../boot.ts";

/**
 * True once setup has run, as distinct from a `.env` merely existing.
 *
 * The file is not the test, because an operator may write one by hand before
 * ever starting the console — a domain, some ports, a password — and that file
 * describes a stack that has not been built yet. Treating its presence as
 * "configured" showed them a login page for a server that did not exist, and
 * no way to reach setup at all.
 *
 * `JWT_SECRET` is the test instead: it is generated, never something anybody
 * writes by hand, and nothing in the stack works without it.
 */
export function isConfigured(): boolean {
  return setting("JWT_SECRET") !== undefined;
}

/**
 * Whether this stack was *set up* for local testing, as opposed to switched
 * onto the LAN afterwards.
 *
 * The two look alike from the outside and are not the same thing. A stack set
 * up this way has no domain and no certificate and never will; a real one with
 * the switch thrown is still a real server, and everything goes back when the
 * switch does.
 */
function setupWasLocal(): boolean {
  return setting("RIFT_LOCAL_TESTING") === "true";
}

/**
 * The routing to hand an operator who brought their own reverse proxy, or null
 * on a stack running its own Caddy.
 */
function ownProxyRoutes(templateRoot: string) {
  if (setting("RIFT_OWN_PROXY") !== "true") return Promise.resolve(null);
  const port = (name: string, fallback: number) => {
    const value = Number(setting(name));
    return Number.isInteger(value) && value > 0 ? value : fallback;
  };
  return proxyRoutes(
    templateRoot,
    setting("RIFT_DOMAIN") ?? "",
    port("RIFT_PROXY_PORT", 8000),
    { udp: port("LIVEKIT_UDP_PORT", 7882), tcp: port("LIVEKIT_TCP_PORT", 7881) },
  );
}

/** The LAN switch, as the dashboard draws it. */
function describeLocal(local: LocalTesting | null) {
  return {
    on: local !== null,
    address: local?.address ?? "",
    port: local?.port ?? DEFAULT_API_PORT,
    serverUrl: publicUrl(local),
    livekitUrl: livekitUrl(local),
    // Where switching back goes. Named on the button, so pressing it is not a
    // guess about what "back" means.
    home: publicUrl(null),
  };
}

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

/**
 * A failure the operator can read, without the query that caused it.
 *
 * psql answers with the statement, its line number and a caret — useful in a
 * terminal, and a description of the schema on a web page. The full text goes
 * to the container log, where the person who can already read the database is
 * the only one who sees it.
 */
function failure(context: string, error: unknown): Response {
  console.error(`[${context}]`, error);
  const message = error instanceof Error ? error.message : String(error);
  const clean = message.startsWith("psql:")
    ? "The database refused that. See `docker compose logs console` for the reason."
    : message;
  return json({ error: clean }, 400);
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

  // Before setup there is no password, because the file that would hold one
  // has not been written yet. That window is safe only because the console is
  // published on the loopback — an operator who moves it to 0.0.0.0 *before*
  // running setup would be handing the Docker socket to the network, so that
  // combination is refused outright rather than trusted to be deliberate.
  const password = configuredPassword();
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
      // An encrypted backup extracted here is a server waiting for its
      // passphrase, not one waiting to be set up from scratch.
      if (await sealedBackupPresent(paths.projectDir)) return html(restorePage());
      return html(setupPage(fields, optionsFromEnv(paths.projectDir)));
    }
    return html(dashboardPage(
      setupWasLocal()
        ? `${setting("RIFT_LOCAL_ADDRESS") ?? ""}:${setting("RIFT_LOCAL_PORT") ?? ""}`
        : setting("RIFT_DOMAIN") ?? "Your server",
      setupWasLocal(),
    ));
  }

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
    return setupStream(await request.json());
  }

  if (path === "/api/status") {
    const target = targetFromEnv();
    const [services, checks, local, proxy, rotations] = await Promise.all([
      serviceStatuses(),
      runChecks(target, paths.migrationsDir).catch(() => []),
      readLocalTesting(target).catch(() => null),
      ownProxyRoutes(paths.templateRoot).catch(() => null),
      lastRotated(target).catch(() => null),
    ]);
    return json({
      services,
      checks,
      secrets: visibleSecrets(),
      // Absent on a stack that was set up for local testing: the switch would
      // be asking to move a LAN address onto a LAN address.
      local: setupWasLocal() ? null : describeLocal(local),
      // Present only when this stack does not run Caddy because somebody else
      // is terminating TLS for it. Nothing else needs the routing.
      proxy,
      // When each secret was last replaced. Null when the state table could
      // not be read, which the page shows as nothing rather than as "never".
      rotations,
    });
  }

  if (path === "/api/local-testing" && request.method === "POST") {
    if (setupWasLocal()) {
      return json({
        error: "This stack was set up for local testing, so it is already on " +
          "your network.",
      }, 409);
    }
    const { on, address, port } = await request.json();
    try {
      if (on) {
        const local = await turnOn(
          targetFromEnv(),
          String(address ?? ""),
          Number(port ?? DEFAULT_API_PORT),
        );
        return json(describeLocal(local));
      }
      // The URL a server would have been given had the switch never been
      // thrown — where anything created while it was on ends up.
      await turnOff(targetFromEnv(), livekitUrl());
      return json(describeLocal(null));
    } catch (error) {
      return failure("local-testing", error);
    }
  }

  if (path === "/api/servers") {
    const target = targetFromEnv();
    const [servers, invites, local] = await Promise.all([
      listServers(target).catch(() => []),
      listInvites(target).catch(() => []),
      readLocalTesting(target).catch(() => null),
    ]);
    return json({
      servers,
      // One live invite per server is all the dashboard offers: a list of every
      // outstanding code would be a list of ways into the server, on a page.
      invites: servers.map((server) => {
        const invite = invites.find((i) => i.serverId === server.id);
        return invite
          ? { serverId: server.id, link: inviteLinkFor(invite.code, local) }
          : null;
      }).filter((entry) => entry !== null),
    });
  }

  if (path === "/api/servers/create" && request.method === "POST") {
    const { name } = await request.json();
    try {
      const created = await createServer(
        String(name ?? ""),
        await readLocalTesting(targetFromEnv()).catch(() => null),
      );
      return json(created);
    } catch (error) {
      return failure("servers/create", error);
    }
  }

  if (path === "/api/servers/invite" && request.method === "POST") {
    const { serverId, maxUses } = await request.json();
    const target = targetFromEnv();
    try {
      const code = await mintInvite(
        target,
        String(serverId),
        Number(maxUses ?? 1),
      );
      const local = await readLocalTesting(target).catch(() => null);
      return json({ link: inviteLinkFor(code, local) });
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : String(error) }, 400);
    }
  }

  if (path === "/api/version") {
    const work = await pendingWork(targetFromEnv(), paths).catch(() => null);
    return json(
      work === null ? { unknown: true } : work,
    );
  }

  if (path === "/api/upgrade" && request.method === "POST") {
    try {
      const result = await applyUpgrade(targetFromEnv(), paths);
      return json(result);
    } catch (error) {
      return failure("upgrade", error);
    }
  }

  if (path === "/api/rotate" && request.method === "POST") {
    if (!isConfigured()) {
      return json({
        error: "This stack has not been set up, so there is nothing to replace.",
      }, 409);
    }
    const { kind } = await request.json();
    if (!isRotationKind(kind)) {
      return json({ error: "Nothing by that name can be replaced." }, 400);
    }
    try {
      return json({ kind, rotatedAt: await rotate(kind, paths) });
    } catch (error) {
      return failure(`rotate ${kind}`, error);
    }
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
    return restoreStream(String(passphrase ?? ""), paths);
  }

  if (path === "/api/backups") {
    return json({ files: await listBackups(paths.projectDir), ...backupStatus() });
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

  if (path === "/api/restart" && request.method === "POST") {
    try {
      const result = await restartStack();
      return json({ ok: result.ok, error: result.ok ? undefined : result.stderr });
    } catch (error) {
      return failure("restart", error);
    }
  }

  if (path === "/api/restart-service" && request.method === "POST") {
    const { service } = await request.json();
    const known = await servicesIn(["full", "studio"]);
    if (!known.includes(String(service))) {
      return json({ error: "No such service in this stack." }, 400);
    }
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
/** One row of the dashboard's credentials panel. */
interface VisibleSecret {
  name: string;
  value: string;
  /** Masked until the operator asks for it, and worth a warning when they do. */
  secret: boolean;
  /** Why it matters, shown beside a revealed value. */
  note?: string;
}

function visibleSecrets(): VisibleSecret[] {
  const entries: (VisibleSecret | null)[] = [
    // The stack's own addresses, which the LAN switch deliberately does not
    // change: this panel is what the server *is*, and the local-testing panel
    // owns where it is temporarily pointed. Derived rather than written out as
    // `https://<domain>`, so a stack set up for local testing does not claim a
    // scheme and a name it has never had.
    { name: "Server URL", value: publicUrl(), secret: false },
    { name: "LiveKit URL", value: livekitUrl(), secret: false },
    // The publishable key, because that is what the server actually issues to
    // clients. Showing the legacy JWT beside it would invite somebody to paste
    // the one nothing hands out any more.
    //
    // Masked even though every member of the server holds a copy: it is handed
    // out per member by `resolve_invite`, not published, and it is the key that
    // reaches this server's API at all. A dashboard that draws it in plain text
    // by default puts it in every screenshot and every shared screen.
    keyRow(setting("SUPABASE_PUBLISHABLE_KEY")),
  ];
  return entries.filter((entry): entry is VisibleSecret => entry !== null);
}

function keyRow(value: string | undefined): VisibleSecret | null {
  if (!value) return null;
  return {
    name: "Publishable key",
    value,
    secret: true,
    note: "Anyone holding this can reach this server's API as an anonymous " +
      "caller. Members receive it automatically when they join — you never " +
      "need to send it to anybody, and it does not belong in a screenshot.",
  };
}

/**
 * Run setup, streaming one JSON object per line as each step lands.
 *
 * Newline-delimited JSON rather than server-sent events: the page needs no
 * reconnection and no event types, and a plain stream is one `getReader()`
 * loop on the other end. Pulling images can take minutes, and a request that
 * returns nothing for that long reads as a hang.
 */
function setupStream(request: Partial<SetupOptions>): Response {
  const encoder = new TextEncoder();

  const body = new ReadableStream({
    async start(controller) {
      const send = (value: unknown) =>
        controller.enqueue(encoder.encode(JSON.stringify(value) + "\n"));

      try {
        // Anything the page did not send falls back to the .env-or-default
        // set, so a caller posting only a domain still gets a whole stack.
        const result = await runSetup(
          { ...optionsFromEnv(defaultPaths().projectDir), ...request },
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

/**
 * Open an encrypted backup and restore it, reporting each step as it lands.
 *
 * A wrong passphrase fails before anything is written, so the page can simply
 * ask again.
 */
function restoreStream(passphrase: string, paths: Paths): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    async start(controller) {
      const send = (value: unknown) =>
        controller.enqueue(encoder.encode(JSON.stringify(value) + "\n"));
      try {
        send({ step: "Opening the backup", done: false });
        await openSealedBackup(paths.projectDir, passphrase);
        send({ step: "Opening the backup", done: true });
        await prepareStack(paths, (step) => send({ step, done: false }));
        send({ restored: true });
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
      "X-Accel-Buffering": "no",
    },
  });
}
