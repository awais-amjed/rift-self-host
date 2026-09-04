/**
 * Who may drive the console.
 *
 * The console mounts the Docker socket, which is root on the host, and holds
 * the service-role key, which is every message on the server. It is bound to
 * the loopback for that reason — but "bound to the loopback" is one `docker
 * compose` edit away from not being true, and on a shared machine every local
 * user reaches the loopback anyway. So it also wants a password.
 *
 * Sessions are a random token in a cookie, kept in memory. Losing them on a
 * restart is the correct behaviour rather than a limitation: the console is
 * restarted by upgrades, and an upgrade is a fine moment to have to log in.
 */
import { timingSafeEqual } from "jsr:@std/crypto@1/timing-safe-equal";
import { encodeHex } from "jsr:@std/encoding@1/hex";
import { setting } from "../env_file.ts";

/** How long a session lasts without being used. */
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const COOKIE_NAME = "rift_console";

/** Live sessions, by token. */
const sessions = new Map<string, number>();

/**
 * The password setup wrote, or null before it has run.
 *
 * From the `.env` file rather than this process's environment, so a password
 * generated during setup protects the console immediately — it cannot restart
 * itself to pick up a new environment, being the container that would be
 * replaced.
 */
export function configuredPassword(): string | null {
  return setting("CONSOLE_PASSWORD") ?? null;
}

/**
 * Compare an attempt against the real password without leaking a prefix.
 *
 * Both sides are hashed first, so the comparison is over two fixed 32-byte
 * digests. `timingSafeEqual` alone would short-circuit on differing lengths
 * and tell an attacker how long the password is; that is a small leak, but
 * hashing costs nothing here and removes the question.
 */
export async function passwordMatches(
  attempt: string,
  expected: string,
): Promise<boolean> {
  const [a, b] = await Promise.all([digest(attempt), digest(expected)]);
  return timingSafeEqual(a, b);
}

async function digest(value: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Start a session and return the cookie to set. */
export function openSession(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = encodeHex(bytes);
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

/** Forget a session. */
export function closeSession(token: string): void {
  sessions.delete(token);
}

/** The session token in [request], if it carries one. */
export function tokenFrom(request: Request): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;

  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE_NAME) return rest.join("=");
  }
  return null;
}

/** True if [request] carries a live session. */
export function isAuthenticated(request: Request): boolean {
  const token = tokenFrom(request);
  if (!token) return false;

  const expiry = sessions.get(token);
  if (expiry === undefined) return false;
  if (expiry < Date.now()) {
    sessions.delete(token);
    return false;
  }

  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return true;
}

/**
 * The `Set-Cookie` value for [token].
 *
 * `Secure` is deliberately absent: the console is reached over plain HTTP on
 * the loopback or through an SSH tunnel, and a Secure cookie would be dropped
 * by the browser in both cases, making login silently fail to stick.
 */
export function sessionCookie(token: string | null): string {
  if (token === null) {
    return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
  }
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${
    Math.floor(SESSION_TTL_MS / 1000)
  }`;
}
