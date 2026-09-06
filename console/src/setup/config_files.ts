/**
 * Turning the operator's two answers and a set of generated secrets into the
 * files the stack reads.
 *
 * Four destinations, all under the project directory so an operator can read
 * what was written and a backup can capture it:
 *
 *   .env                      what docker compose substitutes
 *   volumes/api/kong.yml      routes, with the API keys baked in
 *   volumes/caddy/Caddyfile   the domain to get a certificate for
 *   volumes/livekit/livekit.yaml
 *   volumes/db/*.sql          Postgres' first-boot scripts, copied as-is
 *
 * Templates are rendered by replacing `{{NAME}}`. Deliberately not a template
 * engine: two of these files contain `$(...)` and `${...}` that belong to Kong
 * and to Docker, and anything cleverer would try to interpret them.
 */
import { join } from "jsr:@std/path@1";
import type { SetupOptions } from "./options.ts";
import type { StackSecrets } from "./secrets.ts";

/** What the operator chose. */
export type StackConfig = SetupOptions;

/** Everything needed to render. */
export interface RenderContext extends StackConfig {
  secrets: StackSecrets;
}

/** Substitute every `{{NAME}}` in [template] from [values]. */
export function render(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_match, name: string) => {
    const value = values[name];
    if (value === undefined) {
      throw new Error(`Template refers to {{${name}}}, which was not provided`);
    }
    return value;
  });
}

/**
 * The address clients reach this server at, scheme included.
 *
 * Everything downstream derives from it: what goes in `.env`, the LiveKit URL
 * `create_server` stores, and the invite link an operator pastes. HTTPS on a
 * name for a real server; plain HTTP on a LAN address for a throwaway one.
 */
export function publicUrlFor(options: StackConfig): string {
  return options.localTesting
    ? `http://${options.localAddress.trim()}:${options.localPort}`
    : `https://${options.domain.trim()}`;
}

/** The placeholder values every template is rendered against. */
export function placeholders(context: RenderContext): Record<string, string> {
  const { secrets } = context;
  return {
    DOMAIN: context.domain,
    ANON_KEY: secrets.anonKey,
    SERVICE_ROLE_KEY: secrets.serviceRoleKey,
    PUBLISHABLE_KEY: secrets.publishableKey,
    SECRET_KEY: secrets.secretKey,
    ANON_KEY_ASYMMETRIC: secrets.anonKeyAsymmetric,
    SERVICE_ROLE_KEY_ASYMMETRIC: secrets.serviceRoleKeyAsymmetric,
    LIVEKIT_API_KEY: secrets.livekitApiKey,
    LIVEKIT_API_SECRET: secrets.livekitApiSecret,
  };
}

/**
 * The `.env` docker compose reads.
 *
 * Written with restrictive permissions: it holds the service-role key, which
 * is unrestricted access to every message and member on the server.
 */
export function renderEnv(context: RenderContext): string {
  const { secrets } = context;
  const lines = [
    "# Written by the Rift console. Every value here was generated; none of it",
    "# needs to be edited by hand, and changing JWT_SECRET invalidates both API",
    "# keys below and every session already issued.",
    "",
    `RIFT_DOMAIN=${context.domain}`,
    `RIFT_SERVER_NAME=${context.serverName}`,
    `API_EXTERNAL_URL=${publicUrlFor(context)}`,
    "",
    "# A throwaway stack on a LAN address, over plain HTTP. Recorded so the",
    "# console can keep saying so on the dashboard — it is not a mode a server",
    "# grows out of, because its address is part of every member's identity.",
    `RIFT_LOCAL_TESTING=${context.localTesting}`,
    `RIFT_LOCAL_ADDRESS=${context.localAddress}`,
    `RIFT_LOCAL_PORT=${context.localPort}`,
    "",
    "# Published ports. Every one has a standard default in the compose file;",
    "# these are here so a host that already uses 80 or 443 can move them, and",
    "# so re-running setup remembers what was chosen.",
    `HTTP_PORT=${context.httpPort}`,
    `HTTPS_PORT=${context.httpsPort}`,
    `LIVEKIT_TCP_PORT=${context.livekitTcpPort}`,
    `LIVEKIT_UDP_PORT=${context.livekitUdpPort}`,
    "",
    "# Postgres",
    `POSTGRES_PASSWORD=${secrets.postgresPassword}`,
    "",
    "# The EC keypair GoTrue signs sessions with, and the public half every",
    "# service verifies them against. Not optional: the edge functions verify",
    "# callers locally against the JWKS, and a stack with only JWT_SECRET signs",
    "# HS256 and publishes an empty JWKS, so every authenticated call fails.",
    `JWT_KEYS=${JSON.stringify(secrets.signingKeys.signing)}`,
    `JWT_JWKS=${JSON.stringify(secrets.signingKeys.verifying)}`,
    "",
    "# The shared secret. Still here because the JWKS above carries it too, so",
    "# tokens signed before a stack had an EC key keep verifying.",
    `JWT_SECRET=${secrets.jwtSecret}`,
    "JWT_EXPIRY=3600",
    "",
    "# What clients present. The opaque pair is what they are given; Kong swaps",
    "# each for the signed JWT beside it before passing the request on. The",
    "# legacy pair is still accepted, so a client holding an older key works.",
    `SUPABASE_PUBLISHABLE_KEY=${secrets.publishableKey}`,
    `SUPABASE_SECRET_KEY=${secrets.secretKey}`,
    `ANON_KEY_ASYMMETRIC=${secrets.anonKeyAsymmetric}`,
    `SERVICE_ROLE_KEY_ASYMMETRIC=${secrets.serviceRoleKeyAsymmetric}`,
    `ANON_KEY=${secrets.anonKey}`,
    `SERVICE_ROLE_KEY=${secrets.serviceRoleKey}`,
    "",
    "# Realtime. REALTIME_SEED is true for the first boot only — it is what",
    "# creates the tenant row, whose encrypted settings cannot practically be",
    "# written by hand — and setup rewrites it to false immediately after,",
    "# because leaving it on resets the rate limits on every restart.",
    `SECRET_KEY_BASE=${secrets.secretKeyBase}`,
    `REALTIME_DB_ENC_KEY=${secrets.realtimeEncryptionKey}`,
    "REALTIME_SEED=true",
    "",
    "# LiveKit. Also stored in server_secrets, which is where the edge",
    "# functions read them from to mint join tokens.",
    `LIVEKIT_API_KEY=${secrets.livekitApiKey}`,
    `LIVEKIT_API_SECRET=${secrets.livekitApiSecret}`,
    "",
    "# The console's own password, and where it listens. Moving it off the",
    "# loopback exposes an interface that can replace any container on this",
    "# host; put it behind a tunnel instead.",
    `CONSOLE_PASSWORD=${secrets.consolePassword}`,
    `CONSOLE_BIND=${context.consoleBind}`,
    `CONSOLE_PORT=${context.consolePort}`,
    "",
  ];
  return lines.join("\n");
}

/** Where a rendered file goes, relative to the project directory. */
const RENDERED = [
  { template: "api/kong.yml", destination: "volumes/api/kong.yml" },
  { template: "caddy/Caddyfile", destination: "volumes/caddy/Caddyfile" },
  { template: "livekit/livekit.yaml", destination: "volumes/livekit/livekit.yaml" },
] as const;

/** Postgres' first-boot scripts, copied rather than rendered. */
const DB_SCRIPTS = [
  "roles.sql",
  "jwt.sql",
  "realtime.sql",
  "webhooks.sql",
  "_supabase.sql",
] as const;

/**
 * Write every configuration file for [context].
 *
 * [templateRoot] is where the console image keeps its copies; [projectDir] is
 * the directory holding docker-compose.yml, which is the same path inside this
 * container and on the host.
 */
export async function writeConfigFiles(
  context: RenderContext,
  options: { templateRoot: string; projectDir: string },
): Promise<string[]> {
  const { templateRoot, projectDir } = options;
  const values = placeholders(context);
  const written: string[] = [];

  for (const { template, destination } of RENDERED) {
    const source = await Deno.readTextFile(join(templateRoot, template));
    const path = join(projectDir, destination);
    await Deno.mkdir(join(path, ".."), { recursive: true });
    await Deno.writeTextFile(path, render(source, values));
    written.push(destination);
  }

  const dbDirectory = join(projectDir, "volumes/db");
  await Deno.mkdir(dbDirectory, { recursive: true });
  for (const script of DB_SCRIPTS) {
    await Deno.copyFile(
      join(templateRoot, "db", script),
      join(dbDirectory, script),
    );
    written.push(`volumes/db/${script}`);
  }

  // Local testing publishes what Caddy would otherwise front, because there is
  // no Caddy: a certificate cannot be issued for a LAN address. Written as an
  // override rather than into the compose file so the file an operator
  // downloaded stays the file they downloaded, and so deleting one file undoes
  // the whole arrangement.
  const overridePath = join(projectDir, "docker-compose.override.yml");
  if (context.localTesting) {
    await Deno.writeTextFile(
      overridePath,
      renderLocalOverride(context.localAddress, context.localPort),
    );
    written.push("docker-compose.override.yml");
  } else {
    // A stack set up for real must not inherit a previous run's override — it
    // would publish the API in the clear beside the TLS that replaced it.
    await Deno.remove(overridePath).catch(() => {});
  }

  // Last, and with a mode of its own: until this exists, `docker compose` has
  // no values for the `full` profile, so a half-written stack cannot start.
  const envPath = join(projectDir, ".env");
  await Deno.writeTextFile(envPath, renderEnv(context), { mode: 0o600 });
  written.push(".env");

  return written;
}

/**
 * The compose override a throwaway LAN stack needs.
 *
 * Two things Caddy would have done, done directly: publish the API, and publish
 * LiveKit's signalling. Media was already going straight to a published UDP
 * port and never touched Caddy, which is why that part is unchanged.
 *
 * `LIVEKIT_RTC_NODE_IP` is the one that is not obvious. `use_external_ip` asks
 * STUN which address the internet sees, which is right on a public host and
 * wrong behind a home router — it answers with the *router's* address, so
 * clients on the same network send audio out to the internet expecting it back,
 * and the call connects with no sound.
 */
export function renderLocalOverride(address: string, port: number): string {
  return `# Written by the Rift console for a local-testing stack. Delete it and the
# stack stops being reachable over plain HTTP.
#
# This server has no certificate and no name. It cannot become a real one:
# every member's identity is derived from the address they joined at, so
# changing it makes them strangers. Build a real server when you want one.
services:
  kong:
    ports:
      - "0.0.0.0:${port}:8000"

  livekit:
    ports:
      - "0.0.0.0:7880:7880"
    environment:
      LIVEKIT_RTC_USE_EXTERNAL_IP: "false"
      LIVEKIT_RTC_NODE_IP: "${address}"
`;
}
