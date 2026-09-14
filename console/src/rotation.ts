/**
 * Replacing a stack's secrets after setup.
 *
 * Setup generates every secret once, and until this existed that was the only
 * time. A leaked key had no remedy short of building a new stack, which is no
 * remedy at all: a server's address and every member's identity are permanent.
 *
 * Three rotations, divided by what each costs the people using the server
 * rather than by which files it touches:
 *
 * - **Voice credentials.** Held by LiveKit and by `server_secrets`, nowhere a
 *   client can see. Calls in progress drop and reconnect.
 * - **The database password.** Seven roles, and every service that connects
 *   as one of them. The server is unreachable while those restart.
 * - **Signing keys.** Everything a token is checked against, and every key
 *   signed with it. Members are signed out and straight back in — the app and
 *   the bot SDK both log in again on a rejected token — because the
 *   publishable key they log in with is deliberately kept.
 *
 * The third is shaped the way it is for a reason worth keeping. Replacing only
 * the `sb_secret_` key looks like revoking service access and is not: Kong
 * passes a caller's own `Authorization` header straight through, so a leaked
 * service-role JWT sent beside the publishable key still reads
 * `server_secrets` for as long as anything trusts the key that signed it.
 * Verified against a running stack, with both the HS256 and the ES256 one. A
 * JWT is revoked only by no longer trusting its signer.
 *
 * Each rotation changes the running system in the order that keeps a failure
 * recoverable, and puts back what it changed if a later step fails. None of
 * them has an undo afterwards: the point is that the old value stops working.
 */
import { SignJWT } from "npm:jose@5";
import { join } from "jsr:@std/path@1";
import { readEnvFile, updateSettings } from "./env_file.ts";
import { literal, type PostgresTarget, runSql, targetFromEnv } from "./postgres.ts";
import { recreateServices, serviceStatuses } from "./docker.ts";
import { readState, writeState } from "./state.ts";
import {
  livekitSettings,
  rerender,
  secretsFromEnv,
  signingSettings,
} from "./setup/config_files.ts";
import { adminTarget, TENANT } from "./setup/realtime.ts";
import {
  generateLivekitCredentials,
  generateSigningSecrets,
  type LivekitCredentials,
  randomString,
} from "./setup/secrets.ts";
import type { Jwk } from "./setup/signing_keys.ts";

/** The three things that can be rotated. */
export type RotationKind = "livekit" | "database" | "signing";

export const ROTATION_KINDS: readonly RotationKind[] = ["livekit", "database", "signing"];

/** Whether [value] names a rotation, for a request body nobody has checked. */
export function isRotationKind(value: unknown): value is RotationKind {
  return typeof value === "string" &&
    (ROTATION_KINDS as readonly string[]).includes(value);
}

/** How each is referred to in a sentence. */
export const ROTATION_NAMES: Record<RotationKind, string> = {
  livekit: "the voice credentials",
  database: "the database password",
  signing: "the signing keys",
};

/** Where the console's templates are, and the project it is rotating. */
export interface RotationPaths {
  templateRoot: string;
  projectDir: string;
}

/**
 * Every role whose password is `POSTGRES_PASSWORD`.
 *
 * Read off a running stack rather than off the init scripts: each of these
 * accepts that password over the network, and `supabase_replication_admin`
 * and `supabase_read_only_user` do not. Setting theirs would be giving them a
 * password nothing holds.
 */
export const DATABASE_ROLES = [
  "postgres",
  "supabase_admin",
  "authenticator",
  "pgbouncer",
  "supabase_auth_admin",
  "supabase_functions_admin",
  "supabase_storage_admin",
] as const;

/**
 * Which services read what each rotation changes, and so must be recreated.
 *
 * Neither the database nor the console appears in any of them. The database
 * holds the passwords being changed and never reads `POSTGRES_PASSWORD` again
 * after first boot; the console is the process doing the changing, and reads
 * `.env` afresh on every use anyway.
 */
export const AFFECTED: Record<RotationKind, readonly string[]> = {
  livekit: ["livekit"],
  database: ["auth", "rest", "realtime", "storage", "functions", "studio", "meta"],
  signing: ["kong", "auth", "rest", "realtime", "storage", "functions", "studio"],
};

/**
 * The affected services this stack actually has.
 *
 * Studio and meta exist only once the `studio` profile has been started, and
 * `up --force-recreate` on a service that has never run would start it.
 */
export function servicesToRecreate(
  kind: RotationKind,
  present: readonly string[],
): string[] {
  return AFFECTED[kind].filter((service) => present.includes(service));
}

/** SQL giving every role in [DATABASE_ROLES] [password]. */
export function passwordStatements(password: string): string {
  return DATABASE_ROLES.map((role) =>
    `ALTER ROLE ${role} WITH PASSWORD ${literal(password)};`
  )
    .join("\n");
}

/**
 * SQL moving every server on this stack's LiveKit to [next].
 *
 * Scoped to rows holding [currentKey]. `update_server` lets an admin point a
 * server at a LiveKit somewhere else entirely, and those rows hold somebody
 * else's credentials — not this stack's to replace.
 */
export function livekitStatement(currentKey: string, next: LivekitCredentials): string {
  return `UPDATE server_secrets
   SET livekit_api_key = ${literal(next.livekitApiKey)},
       livekit_secret_key = ${literal(next.livekitApiSecret)}
 WHERE livekit_api_key = ${literal(currentKey)};`;
}

/**
 * [yaml] with LiveKit's key pair swapped, and nothing else touched.
 *
 * Edited in place rather than re-rendered, unlike kong.yml, because this is the
 * one generated file operators are told to change: a busy server widens
 * `udp_port` to a range here (docs.joinrift.app/reference/#media), and
 * rendering the template again would quietly put it back to a single port.
 *
 * Refuses rather than guesses when the current pair is not there. The message
 * names no key — it ends up on a dashboard.
 */
export function withLivekitKey(
  yaml: string,
  current: LivekitCredentials,
  next: LivekitCredentials,
): string {
  const lines = yaml.split("\n");
  const index = lines.findIndex((line) =>
    line.trimEnd() === `  ${current.livekitApiKey}: ${current.livekitApiSecret}`
  );
  if (index === -1) {
    throw new Error(
      "volumes/livekit/livekit.yaml does not list the key in .env, so it has been " +
        "edited by hand. Make its keys entry match LIVEKIT_API_KEY and " +
        "LIVEKIT_API_SECRET, then try again.",
    );
  }
  lines[index] = `  ${next.livekitApiKey}: ${next.livekitApiSecret}`;
  return lines.join("\n");
}

/**
 * SQL keeping the database's own copy of the shared secret in step.
 *
 * Nothing in Rift's schema reads `app.settings.jwt_secret`, and PostgREST sets
 * its own per request. It is updated anyway because `jwt.sql` set it at first
 * boot, and a value that silently stops being true is a trap for whoever reads
 * it next.
 */
export function jwtSettingStatement(secret: string): string {
  return `ALTER DATABASE postgres SET "app.settings.jwt_secret" TO ${literal(secret)};`;
}

// ────────────────────────────────────────────────────────────────────────────
// Against the running stack
// ────────────────────────────────────────────────────────────────────────────

/** Realtime's management API, from inside the compose network. */
const REALTIME_TENANT_API = `http://realtime:4000/api/tenants/${TENANT}`;

/**
 * Give Realtime's tenant row a new secret and key set.
 *
 * Realtime keeps both in its own table, not only in its environment, and with
 * the seed off (see realtime.ts) nothing copies a changed `.env` into that
 * row. Left alone, every member's subscription would be refused after a
 * rotation while the rest of the server worked.
 *
 * Through the API rather than an UPDATE, because the stored secret is
 * encrypted with `REALTIME_DB_ENC_KEY` in Realtime's own format. The API
 * authenticates with a token signed by [apiSecret], which must be the secret
 * the running container was started with. The update does not clear
 * Realtime's cache, so the container still has to be recreated afterwards.
 */
async function updateRealtimeTenant(
  apiSecret: string,
  jwtSecret: string,
  jwks: { keys: Jwk[] },
): Promise<void> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ role: "service_role" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + 300)
    .sign(new TextEncoder().encode(apiSecret));

  const response = await fetch(REALTIME_TENANT_API, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ tenant: { jwt_secret: jwtSecret, jwt_jwks: jwks } }),
    signal: AbortSignal.timeout(15_000),
  });
  await response.body?.cancel();
  if (!response.ok) {
    throw new Error(
      `Realtime would not take the new signing keys (HTTP ${response.status}).`,
    );
  }
}

/**
 * Run SQL that carries a secret, in one transaction, or throw.
 *
 * psql quotes the offending statement back when one fails, so its error is
 * scrubbed of [secrets] before it goes anywhere — the log, and from there the
 * dashboard.
 */
async function runSecretSql(
  target: PostgresTarget,
  sql: string,
  secrets: string[],
  what: string,
): Promise<void> {
  const result = await runSql(target, sql, { singleTransaction: true });
  if (result.ok) return;
  const scrubbed = secrets.reduce(
    (text, secret) => text.replaceAll(secret, "[redacted]"),
    result.error,
  );
  console.error(`[rotate] ${what}:`, scrubbed);
  throw new Error(`The database refused ${what}. See \`docker compose logs console\`.`);
}

/** Recreate what [kind] affects on this stack. */
async function recreateFor(kind: RotationKind): Promise<void> {
  const present = (await serviceStatuses()).map((service) => service.name);
  await recreateServices(servicesToRecreate(kind, present));
}

/**
 * New voice credentials.
 *
 * The file and the database first, LiveKit last: it is the step that can fail
 * for reasons outside this code, and if it does the other two are put back
 * before it is tried again.
 */
async function rotateLivekit(
  target: PostgresTarget,
  paths: RotationPaths,
): Promise<void> {
  const current = secretsFromEnv(readEnvFile(paths.projectDir));
  const next = generateLivekitCredentials();
  const admin = adminTarget(target);
  const yamlPath = join(paths.projectDir, "volumes/livekit/livekit.yaml");
  const yaml = await Deno.readTextFile(yamlPath);
  // Before anything changes: a hand-edited file is refused with nothing to undo.
  const updated = withLivekitKey(yaml, current, next);
  const hidden = [current.livekitApiSecret, next.livekitApiSecret];

  try {
    await Deno.writeTextFile(yamlPath, updated);
    await updateSettings(livekitSettings(next), paths.projectDir);
    await runSecretSql(
      admin,
      livekitStatement(current.livekitApiKey, next),
      hidden,
      "the new voice credentials",
    );
    await recreateFor("livekit");
  } catch (error) {
    await Deno.writeTextFile(yamlPath, yaml).catch(() => {});
    await updateSettings(livekitSettings(current), paths.projectDir).catch(() => {});
    await runSecretSql(
      admin,
      livekitStatement(next.livekitApiKey, current),
      hidden,
      "the old voice credentials",
    )
      .catch(() => {});
    await recreateFor("livekit").catch(() => {});
    throw error;
  }
}

/**
 * A new database password.
 *
 * The roles change first, in one transaction: if Postgres refuses, nothing
 * has happened. Only then is `.env` changed and the services recreated, and a
 * failure there sets the roles back to the password everything still holds.
 */
async function rotateDatabase(
  target: PostgresTarget,
  paths: RotationPaths,
): Promise<void> {
  const current = target.password;
  const next = randomString(32);
  const admin = adminTarget(target);
  const hidden = [current, next];

  await runSecretSql(admin, passwordStatements(next), hidden, "the new password");

  try {
    await updateSettings({ POSTGRES_PASSWORD: next }, paths.projectDir);
    await recreateFor("database");
  } catch (error) {
    await runSecretSql(
      { ...admin, password: next },
      passwordStatements(current),
      hidden,
      "the old password",
    )
      .catch(() => {});
    await updateSettings({ POSTGRES_PASSWORD: current }, paths.projectDir).catch(
      () => {},
    );
    await recreateFor("database").catch(() => {});
    throw error;
  }
}

/**
 * New signing keys, and every key signed with them.
 *
 * Realtime is told first, while it still runs on the old secret its API checks
 * tokens against; it is also the step most likely to refuse, and a refusal
 * there has changed nothing. Then `.env`, kong.yml and the database's copy,
 * and the services last.
 */
async function rotateSigning(
  target: PostgresTarget,
  paths: RotationPaths,
): Promise<void> {
  const current = secretsFromEnv(readEnvFile(paths.projectDir));
  const next = await generateSigningSecrets(current.publishableKey);
  const admin = adminTarget(target);
  const hidden = [current.jwtSecret, next.jwtSecret];

  await updateRealtimeTenant(
    current.jwtSecret,
    next.jwtSecret,
    next.signingKeys.verifying,
  );

  try {
    await updateSettings(signingSettings(next), paths.projectDir);
    await rerender(["volumes/api/kong.yml"], paths);
    await runSecretSql(
      admin,
      jwtSettingStatement(next.jwtSecret),
      hidden,
      "the new signing secret",
    );
    await recreateFor("signing");
  } catch (error) {
    await updateSettings(signingSettings(current), paths.projectDir).catch(() => {});
    await rerender(["volumes/api/kong.yml"], paths).catch(() => {});
    await runSecretSql(
      admin,
      jwtSettingStatement(current.jwtSecret),
      hidden,
      "the old signing secret",
    )
      .catch(() => {});
    // Realtime is running on whichever secret it was last recreated with,
    // which depends on how far the recreate got. Ask with the new one, then the old.
    const previous = current.signingKeys.verifying;
    await updateRealtimeTenant(next.jwtSecret, current.jwtSecret, previous)
      .catch(() => updateRealtimeTenant(current.jwtSecret, current.jwtSecret, previous))
      .catch(() => {});
    await recreateFor("signing").catch(() => {});
    throw error;
  }
}

const OPERATIONS: Record<
  RotationKind,
  (target: PostgresTarget, paths: RotationPaths) => Promise<void>
> = {
  livekit: rotateLivekit,
  database: rotateDatabase,
  signing: rotateSigning,
};

/** Where the time of the last rotation of [kind] is kept. */
function stateKey(kind: RotationKind): string {
  return `rotated_${kind}`;
}

/** The rotation running right now, if any. Two at once would each undo the other. */
let inProgress: RotationKind | null = null;

/**
 * Rotate [kind], and record when. Returns that time.
 *
 * One at a time: a database rotation and a signing rotation both rewrite
 * `.env` and recreate the same services, and interleaved they would each
 * recreate against the other's half-written state.
 */
export async function rotate(kind: RotationKind, paths: RotationPaths): Promise<string> {
  if (inProgress !== null) {
    throw new Error(
      `Already replacing ${ROTATION_NAMES[inProgress]}. Wait for that to finish.`,
    );
  }
  inProgress = kind;
  try {
    await OPERATIONS[kind](targetFromEnv(), paths);
  } finally {
    inProgress = null;
  }

  const at = new Date().toISOString();
  // A fresh target: rotating the database password has just changed the one
  // the last would have connected with. The rotation itself has succeeded, so
  // failing to record the time is logged rather than reported as a failure.
  await writeState(targetFromEnv(), stateKey(kind), at)
    .catch((error) => console.error("[rotate] could not record the time", error));
  return at;
}

/** When each was last rotated, or null for never. */
export async function lastRotated(
  target: PostgresTarget,
): Promise<Record<RotationKind, string | null>> {
  const [livekit, database, signing] = await Promise.all(
    ROTATION_KINDS.map((kind) => readState(target, stateKey(kind))),
  );
  return { livekit, database, signing };
}
