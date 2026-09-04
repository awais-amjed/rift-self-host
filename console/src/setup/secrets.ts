/**
 * Everything the stack needs to be told, generated once.
 *
 * These are the values an operator would otherwise have to produce by hand,
 * and two of them have shapes that are easy to get wrong in ways nothing
 * reports: a Postgres password containing a character that is special inside a
 * connection URI, and a Realtime encryption key that is not exactly sixteen
 * bytes. Both are generated here so neither can happen.
 */
import { SignJWT } from "npm:jose@5";

/** The complete set of generated values. */
export interface StackSecrets {
  postgresPassword: string;
  jwtSecret: string;
  anonKey: string;
  serviceRoleKey: string;
  /** Phoenix's cookie/session signing key. Must be at least 64 bytes. */
  secretKeyBase: string;
  /** Realtime's column encryption key. Must be exactly 16 bytes. */
  realtimeEncryptionKey: string;
  livekitApiKey: string;
  livekitApiSecret: string;
  /** What the operator types to open the console. */
  consolePassword: string;
}

/**
 * Alphanumerics only.
 *
 * Passwords generated from this go into connection strings like
 * `postgres://user:PASSWORD@db:5432/postgres`, where `@`, `:`, `/`, `?`, `#`
 * and `%` each change what the URI means. Every service then fails to reach
 * the database in its own way, none of which mentions the password.
 */
const SAFE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/** How long a JWT API key is good for. */
const API_KEY_LIFETIME_YEARS = 10;

/**
 * A random string of [length] characters from [SAFE_ALPHABET].
 *
 * Rejection sampling rather than a modulo, so every character is equally
 * likely. 62 does not divide 256, and the lazy version quietly makes the first
 * few letters of the alphabet more common than the rest.
 */
export function randomString(length: number): string {
  const limit = 256 - (256 % SAFE_ALPHABET.length);
  let out = "";

  while (out.length < length) {
    const bytes = new Uint8Array(length - out.length + 8);
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte >= limit) continue;
      out += SAFE_ALPHABET[byte % SAFE_ALPHABET.length];
      if (out.length === length) break;
    }
  }

  return out;
}

/**
 * Sign one of the two API keys the stack hands out.
 *
 * These are the `apikey` values every client sends. They are ordinary HS256
 * JWTs signed with the stack's own secret — which is why generating them is
 * something a setup step can do, and why they change whenever [jwtSecret]
 * does.
 */
export async function signApiKey(
  jwtSecret: string,
  role: "anon" | "service_role",
): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + API_KEY_LIFETIME_YEARS * 365 * 24 * 60 * 60;

  return await new SignJWT({ role, iss: "supabase" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .sign(new TextEncoder().encode(jwtSecret));
}

/** Generate a fresh set. Called once, at setup. */
export async function generateSecrets(): Promise<StackSecrets> {
  const jwtSecret = randomString(64);

  return {
    postgresPassword: randomString(32),
    jwtSecret,
    anonKey: await signApiKey(jwtSecret, "anon"),
    serviceRoleKey: await signApiKey(jwtSecret, "service_role"),
    secretKeyBase: randomString(64),
    // Exactly 16. Realtime uses it as an AES-128 key and refuses to boot
    // otherwise, with an Elixir stacktrace rather than a sentence.
    realtimeEncryptionKey: randomString(16),
    // The "API" prefix is LiveKit's convention for identifying a key in logs.
    livekitApiKey: `API${randomString(12)}`,
    livekitApiSecret: randomString(48),
    consolePassword: randomString(24),
  };
}
