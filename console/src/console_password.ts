/**
 * The console password, kept as a hash.
 *
 * Nothing needs the password itself after setup has shown it: the console only
 * ever compares an attempt against it. Kept in the clear it leaked the way
 * plain values do — printed in every startup banner, so `docker compose logs`
 * and anybody reading over a shoulder had it, and on screen whenever `.env` was
 * open. A hash cannot be read back, so a lost password is replaced
 * (`reset-password`), never recovered.
 *
 * `CONSOLE_PASSWORD` is still how a password goes *in*: a hand-written `.env`
 * before setup, a new one typed into the file, an old backup restored. The
 * console swaps it for `CONSOLE_PASSWORD_HASH` the next time it reads the file,
 * except while setup is running, which still needs the plain value to show it
 * once at the end.
 *
 * PBKDF2 because WebCrypto has it and the image needs no new dependency. The
 * scheme and the iteration count are in the stored value, so either can change
 * without stranding a stack that hashed under the old ones. Colons separate the
 * parts because compose reads `$` in `.env` as the start of a variable.
 */
import { timingSafeEqual } from "jsr:@std/crypto@1/timing-safe-equal";
import { decodeHex, encodeHex } from "jsr:@std/encoding@1/hex";
import { readEnvFile, updateSettings } from "./env_file.ts";

/** Where a password goes in, in the clear. */
export const PLAIN_SETTING = "CONSOLE_PASSWORD";

/** Where the console keeps it. */
export const HASH_SETTING = "CONSOLE_PASSWORD_HASH";

const SCHEME = "pbkdf2-sha256";

/** OWASP's figure for PBKDF2-SHA256: a few hundred milliseconds a sign-in. */
const ITERATIONS = 600_000;

/** Hash [password] with a fresh salt, as `scheme:iterations:salt:hash`. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, ITERATIONS);
  return [SCHEME, ITERATIONS, encodeHex(salt), encodeHex(hash)].join(":");
}

/** Whether [attempt] is the password [stored] was made from. */
export async function verifyPassword(attempt: string, stored: string): Promise<boolean> {
  const [scheme, iterations, salt, hash] = stored.split(":");
  const rounds = Number(iterations);
  if (scheme !== SCHEME || !Number.isInteger(rounds) || rounds < 1 || !salt || !hash) {
    return false;
  }

  let expected: Uint8Array<ArrayBuffer>;
  let saltBytes: Uint8Array<ArrayBuffer>;
  try {
    expected = decodeHex(hash);
    saltBytes = decodeHex(salt);
  } catch {
    return false;
  }
  return timingSafeEqual(await derive(attempt, saltBytes, rounds), expected);
}

async function derive(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * The stored hash, or null when there is no password.
 *
 * A plain `CONSOLE_PASSWORD` found here is hashed and taken out of the file in
 * the same write — but not while setup is running, which still has to show it.
 * Read from the file alone, never the process environment, so the line once
 * removed stays removed.
 */
export async function storedPasswordHash(directory?: string): Promise<string | null> {
  const values = readEnvFile(directory);
  const plain = values[PLAIN_SETTING];

  if (plain && values.RIFT_SETUP !== "running") {
    const hash = await hashPassword(plain);
    await updateSettings({ [HASH_SETTING]: hash, [PLAIN_SETTING]: null }, directory);
    return hash;
  }
  return values[HASH_SETTING] || null;
}

/** Replace the password with [password], hashed. */
export async function setPassword(password: string, directory?: string): Promise<void> {
  await updateSettings(
    { [HASH_SETTING]: await hashPassword(password), [PLAIN_SETTING]: null },
    directory,
  );
}
