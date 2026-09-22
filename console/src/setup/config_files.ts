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
import { readEnvFile } from "../env_file.ts";
import { optionsFromEnv, type SetupOptions } from "./options.ts";
import type { LivekitCredentials, SigningSecrets, StackSecrets } from "./secrets.ts";
import type { Jwk } from "./signing_keys.ts";

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
    "# Whether this stack runs its own Caddy. False when the operator already",
    "# terminates TLS here for something else — the compose override then",
    "# publishes Kong and LiveKit's signalling on the loopback for their proxy,",
    "# and `docker compose up` leaves caddy out.",
    `RIFT_OWN_PROXY=${context.ownProxy}`,
    `RIFT_PROXY_PORT=${context.proxyPort}`,
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

/**
 * The signing half of [renderEnv], as settings a rotation can write.
 *
 * Duplicates eight of the names above, deliberately rather than carelessly:
 * `.env` is commented section by section and a loop would lose that. A test
 * checks every pair here is a line [renderEnv] writes, so the two cannot
 * drift.
 */
export function signingSettings(secrets: SigningSecrets): Record<string, string> {
  return {
    JWT_KEYS: JSON.stringify(secrets.signingKeys.signing),
    JWT_JWKS: JSON.stringify(secrets.signingKeys.verifying),
    JWT_SECRET: secrets.jwtSecret,
    SUPABASE_PUBLISHABLE_KEY: secrets.publishableKey,
    SUPABASE_SECRET_KEY: secrets.secretKey,
    ANON_KEY_ASYMMETRIC: secrets.anonKeyAsymmetric,
    SERVICE_ROLE_KEY_ASYMMETRIC: secrets.serviceRoleKeyAsymmetric,
    ANON_KEY: secrets.anonKey,
    SERVICE_ROLE_KEY: secrets.serviceRoleKey,
  };
}

/** LiveKit's pair, the same way. */
export function livekitSettings(credentials: LivekitCredentials): Record<string, string> {
  return {
    LIVEKIT_API_KEY: credentials.livekitApiKey,
    LIVEKIT_API_SECRET: credentials.livekitApiSecret,
  };
}

/**
 * The generated secrets, read back out of a `.env` that [renderEnv] wrote.
 *
 * Kept beside [renderEnv] because it is that function run backwards, and the
 * names are defined there. A rotation needs it to re-render kong.yml after
 * changing some of these values and not the others.
 */
export function secretsFromEnv(values: Record<string, string>): StackSecrets {
  const required = (name: string): string => {
    const value = values[name];
    if (value === undefined || value.length === 0) {
      throw new Error(
        `.env has no ${name}, so this stack's secrets cannot be read back.`,
      );
    }
    return value;
  };

  const signing = JSON.parse(required("JWT_KEYS")) as Jwk[];
  const verifying = JSON.parse(required("JWT_JWKS")) as { keys: Jwk[] };
  const kid = signing.find((key) => key.kty === "EC")?.kid;
  if (typeof kid !== "string") throw new Error("JWT_KEYS in .env has no EC signing key.");

  return {
    postgresPassword: required("POSTGRES_PASSWORD"),
    jwtSecret: required("JWT_SECRET"),
    anonKey: required("ANON_KEY"),
    serviceRoleKey: required("SERVICE_ROLE_KEY"),
    secretKeyBase: required("SECRET_KEY_BASE"),
    realtimeEncryptionKey: required("REALTIME_DB_ENC_KEY"),
    livekitApiKey: required("LIVEKIT_API_KEY"),
    livekitApiSecret: required("LIVEKIT_API_SECRET"),
    consolePassword: required("CONSOLE_PASSWORD"),
    signingKeys: { signing, verifying, kid },
    publishableKey: required("SUPABASE_PUBLISHABLE_KEY"),
    secretKey: required("SUPABASE_SECRET_KEY"),
    anonKeyAsymmetric: required("ANON_KEY_ASYMMETRIC"),
    serviceRoleKeyAsymmetric: required("SERVICE_ROLE_KEY_ASYMMETRIC"),
  };
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

  // Whatever Caddy is not fronting has to be published instead. A stack that
  // *is* behind Caddy writes nothing and clears any override a previous run
  // left, which would otherwise publish the API in the clear beside the TLS
  // that replaced it.
  if (await writeOverride(projectDir, publishingFor(context))) {
    written.push(OVERRIDE_FILE);
  }

  // Last, and with a mode of its own: until this exists, `docker compose` has
  // no values for the `full` profile, so a half-written stack cannot start.
  const envPath = join(projectDir, ".env");
  await Deno.writeTextFile(envPath, renderEnv(context), { mode: 0o600 });
  written.push(".env");

  return written;
}

/** A file [writeConfigFiles] renders, named by where it lands. */
export type RenderedFile = (typeof RENDERED)[number]["destination"];

/**
 * Render [files] again from what `.env` says now.
 *
 * For a rotation, which changes secrets in `.env` and then has to bring the
 * files that bake them in along with it. Reads everything back rather than
 * taking it as arguments, so what is written is exactly what the containers
 * are about to be recreated against.
 */
export async function rerender(
  files: RenderedFile[],
  options: { templateRoot: string; projectDir: string },
): Promise<void> {
  const context: RenderContext = {
    ...optionsFromEnv(options.projectDir),
    secrets: secretsFromEnv(readEnvFile(options.projectDir)),
  };
  const values = placeholders(context);

  for (const { template, destination } of RENDERED) {
    if (!files.includes(destination)) continue;
    const source = await Deno.readTextFile(join(options.templateRoot, template));
    await Deno.writeTextFile(
      join(options.projectDir, destination),
      render(source, values),
    );
  }
}

/**
 * Write whichever generated files are missing, from what `.env` says.
 *
 * A backup is `.env` and a database dump. Everything under `volumes/` is
 * derived from `.env`, and so is the compose override for a stack without
 * Caddy. Restoring one by the docs brought the database up with
 * `volumes/db/roles.sql` absent — and Docker, asked to bind-mount a file that
 * does not exist, creates an empty *directory* in its place. Postgres
 * initialised with no role passwords set, and auth, rest, realtime and storage
 * all failed authentication against a database reporting itself healthy.
 *
 * Never overwrites a file that exists: livekit.yaml is one operators are told
 * to edit. An empty directory Docker left where a file belongs is replaced.
 */
export async function restoreMissingConfig(
  options: { templateRoot: string; projectDir: string },
): Promise<string[]> {
  const { templateRoot, projectDir } = options;
  const context: RenderContext = {
    ...optionsFromEnv(projectDir),
    secrets: secretsFromEnv(readEnvFile(projectDir)),
  };
  const values = placeholders(context);
  const written: string[] = [];

  for (const { template, destination } of RENDERED) {
    const path = join(projectDir, destination);
    if (!await vacant(path)) continue;
    await Deno.mkdir(join(path, ".."), { recursive: true });
    const source = await Deno.readTextFile(join(templateRoot, template));
    await Deno.writeTextFile(path, render(source, values));
    written.push(destination);
  }

  for (const script of DB_SCRIPTS) {
    const destination = `volumes/db/${script}`;
    const path = join(projectDir, destination);
    if (!await vacant(path)) continue;
    await Deno.mkdir(join(projectDir, "volumes/db"), { recursive: true });
    await Deno.copyFile(join(templateRoot, "db", script), path);
    written.push(destination);
  }

  if (
    await vacant(join(projectDir, OVERRIDE_FILE)) &&
    await writeOverride(projectDir, publishingFor(context))
  ) {
    written.push(OVERRIDE_FILE);
  }

  return written;
}

/**
 * Whether [path] holds nothing worth keeping: nothing at all, or the empty
 * directory Docker makes when told to mount a file that is not there — which
 * is removed here so the file can take its place.
 */
async function vacant(path: string): Promise<boolean> {
  try {
    const info = await Deno.stat(path);
    if (!info.isDirectory) return false;
    for await (const _entry of Deno.readDir(path)) return false;
    await Deno.remove(path);
    return true;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return true;
    throw error;
  }
}

/**
 * What this stack publishes on the host, beyond the ports the compose file
 * already names.
 *
 * Three arrangements produce one file between them, which is why this is a
 * shape rather than three renderers. Caddy fronts Kong and LiveKit's
 * signalling on a normal stack, so neither is published and there is nothing
 * to write. Without Caddy — because the operator has their own proxy, or
 * because the stack is a throwaway on a LAN address — both have to be
 * reachable from outside the compose network, and the same two `ports:` blocks
 * are what does it.
 */
export interface Publishing {
  /** Host port for Kong, or null to leave it behind the proxy. */
  apiPort: number | null;
  /**
   * Interface to publish on.
   *
   * `127.0.0.1` for an operator's own proxy, which is on this machine: a
   * signalling port on every interface is LiveKit answering in the clear
   * beside the TLS that was meant to front it. `0.0.0.0` for local testing,
   * where the whole point is that other machines can reach it.
   */
  bind: string;
  /**
   * LAN address to pin LiveKit's media to, or null to leave STUN to it.
   *
   * Only a home network needs this. `use_external_ip` asks STUN which address
   * the internet sees, which is right on a public host and wrong behind a
   * router — it answers with the *router's* address, so clients on the same
   * network send audio out to the internet expecting it back, and the call
   * connects with no sound.
   */
  lanAddress: string | null;
}

/** What a stack with its own Caddy publishes: nothing extra. */
export const behindCaddy: Publishing = {
  apiPort: null,
  bind: "127.0.0.1",
  lanAddress: null,
};

/**
 * The compose override for [publishing], or null when there is nothing to say.
 *
 * Written as an override rather than into the compose file so the file an
 * operator downloaded stays the file they downloaded, and so deleting one file
 * undoes the whole arrangement.
 */
export function renderOverride(publishing: Publishing): string | null {
  const { apiPort, bind, lanAddress } = publishing;
  if (apiPort === null) return null;

  const livekitLan = lanAddress === null ? "" : pinLivekitTo(lanAddress.trim());

  return `${OVERRIDE_MARK}. It publishes what Caddy would otherwise have
# fronted: the API gateway, and LiveKit's signalling. Media was already going
# straight to a published UDP port and never touched Caddy, which is why that
# part is not here.
#
# Delete it and both stop being reachable from outside the compose network.
services:
  kong:
    ports:
      - "${bind}:${apiPort}:8000"

  livekit:
    ports:
      - "${bind}:7880:7880"
${livekitLan}`;
}

/**
 * The part of the override that pins LiveKit's media to [address].
 *
 * Neither of the obvious ways works. LiveKit reads no environment variable for
 * either setting — `LIVEKIT_RTC_NODE_IP` was written here for months and did
 * nothing — and `use_external_ip: true` in livekit.yaml wins over
 * `--node-ip`, so the flag alone still advertises the router's address. So
 * LiveKit starts from a copy of its config with STUN turned off, which leaves
 * livekit.yaml itself, the file operators are told to edit, as it is.
 *
 * `$` would be compose interpolation, and the script needs none.
 */
function pinLivekitTo(address: string): string {
  return `    # Media pinned to the LAN address: STUN would answer with the router's.
    entrypoint:
      - sh
      - -c
      - >-
        sed 's/^\\([[:space:]]*use_external_ip:\\).*/\\1 false/'
        /etc/livekit.yaml > /tmp/livekit.yaml &&
        exec /livekit-server --config /tmp/livekit.yaml --node-ip ${address}
`;
}

/** The first line of every override this console writes. */
export const OVERRIDE_MARK = "# Written by the Rift console";

/** The name compose picks up without being told. */
export const OVERRIDE_FILE = "docker-compose.override.yml";

/** How [options] publishes, before any dashboard switch is thrown. */
export function publishingFor(options: StackConfig): Publishing {
  if (options.localTesting) {
    return {
      apiPort: options.localPort,
      bind: "0.0.0.0",
      lanAddress: options.localAddress,
    };
  }
  if (options.ownProxy) {
    return { apiPort: options.proxyPort, bind: "127.0.0.1", lanAddress: null };
  }
  return behindCaddy;
}

/**
 * Write the override for [publishing] under [projectDir], or remove ours.
 *
 * Removal only ever takes a file this console wrote.
 * `docker-compose.override.yml` is the documented way for an operator to
 * change the stack without editing what they downloaded, so deleting one
 * somebody else put there would silently undo their work.
 */
export async function writeOverride(
  projectDir: string,
  publishing: Publishing,
): Promise<boolean> {
  const path = join(projectDir, OVERRIDE_FILE);
  const body = renderOverride(publishing);
  if (body !== null) {
    await Deno.writeTextFile(path, body);
    return true;
  }
  const existing = await Deno.readTextFile(path).catch(() => null);
  if (existing !== null && existing.startsWith(OVERRIDE_MARK)) {
    await Deno.remove(path).catch(() => {});
  }
  return false;
}
