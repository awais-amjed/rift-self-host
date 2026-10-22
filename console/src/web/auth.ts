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
import { encodeHex } from "jsr:@std/encoding@1/hex";

/** How long a session lasts without being used. */
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const COOKIE_NAME = "rift_console";

/**
 * Live sessions, by token: when each expires, and the password hash it was
 * opened under. A session ends with its password, so `reset-password` after a
 * leak also signs out whoever used the leaked one.
 */
const sessions = new Map<string, { expiry: number; hash: string }>();

/** Start a session under the password [hash] and return its token. */
export function openSession(hash: string): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = encodeHex(bytes);
  sessions.set(token, { expiry: Date.now() + SESSION_TTL_MS, hash });
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

/** True if [request] carries a live session, opened under the password [hash]. */
export function isAuthenticated(request: Request, hash: string): boolean {
  const token = tokenFrom(request);
  if (!token) return false;

  const session = sessions.get(token);
  if (session === undefined) return false;
  if (session.expiry < Date.now() || session.hash !== hash) {
    sessions.delete(token);
    return false;
  }

  session.expiry = Date.now() + SESSION_TTL_MS;
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
