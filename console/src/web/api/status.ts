/**
 * The Overview and Network tabs' endpoints: what is running, the LAN switch,
 * upgrades and restarts.
 */
import { setting } from "../../env_file.ts";
import { runChecks } from "../../health.ts";
import { applyUpgrade, pendingWork } from "../../upgrade.ts";
import { livekitUrl, publicUrl } from "../../servers.ts";
import {
  DEFAULT_API_PORT,
  type LocalTesting,
  readLocalTesting,
  turnOff,
  turnOn,
} from "../../local_testing.ts";
import { proxyRoutes, SIGNALLING_PORT } from "../../proxy.ts";
import { lastRotated } from "../../rotation.ts";
import {
  restartService,
  restartStack,
  servicesIn,
  serviceStatuses,
} from "../../docker.ts";
import { targetFromEnv } from "../../postgres.ts";
import { type ApiRoutes, failure, json } from "../responses.ts";
import { portSetting, setupWasLocal } from "../stack_state.ts";
import { visibleSecrets } from "./security.ts";

export const statusRoutes: ApiRoutes = async (request, url, paths) => {
  const path = url.pathname;

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
      ports: publishedPorts(),
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

  if (path === "/api/version") {
    const work = await pendingWork(targetFromEnv(), paths).catch(() => null);
    return json(work === null ? { unknown: true } : work);
  }

  if (path === "/api/upgrade" && request.method === "POST") {
    try {
      return json(await applyUpgrade(targetFromEnv(), paths));
    } catch (error) {
      return failure("upgrade", error);
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

  return null;
};

/**
 * The routing to hand an operator who brought their own reverse proxy, or null
 * on a stack running its own Caddy.
 */
function ownProxyRoutes(templateRoot: string) {
  if (setting("RIFT_OWN_PROXY") !== "true") return Promise.resolve(null);
  return proxyRoutes(
    templateRoot,
    setting("RIFT_DOMAIN") ?? "",
    portSetting("RIFT_PROXY_PORT", 8000),
    {
      udp: portSetting("LIVEKIT_UDP_PORT", 7882),
      tcp: portSetting("LIVEKIT_TCP_PORT", 7881),
    },
  );
}

/**
 * The ports people's apps connect to, for the Network tab's list of what to
 * open. Which ones depends on who answers web traffic: this stack's Caddy, the
 * operator's own proxy, or nobody, on a stack set up for local testing.
 */
function publishedPorts() {
  return {
    mode: setupWasLocal()
      ? "local"
      : setting("RIFT_OWN_PROXY") === "true"
      ? "proxy"
      : "caddy",
    http: portSetting("HTTP_PORT", 80),
    https: portSetting("HTTPS_PORT", 443),
    api: portSetting("RIFT_LOCAL_PORT", DEFAULT_API_PORT),
    signalling: SIGNALLING_PORT,
    mediaUdp: portSetting("LIVEKIT_UDP_PORT", 7882),
    mediaTcp: portSetting("LIVEKIT_TCP_PORT", 7881),
  };
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
