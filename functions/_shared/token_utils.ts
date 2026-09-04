/**
 * Generates a secure random token — 32 bytes of CSPRNG output, hex-encoded.
 *
 * The token is validated by DB lookup only (not a MAC/signature), so the
 * only security property required is unpredictability, which raw random bytes
 * provide. No HMAC or secret key is needed.
 */
export function generateSecureToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Base58 alphabet (Bitcoin's) — omits 0/O/I/l so codes are easy to read and
// retype. Invite codes go in a shareable link, so short and legible beats the
// 64-char hex session token.
const INVITE_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Generates a short, human-friendly invite code (default 10 base58 chars ≈
 * 58 bits of entropy). Like a session token it's validated by DB lookup only,
 * so unpredictability is the only requirement; single-use + expiry keep the
 * shorter code safe. Uses rejection sampling to avoid modulo bias.
 */
export function generateInviteCode(length = 10): string {
  const n = INVITE_ALPHABET.length; // 58
  const limit = Math.floor(256 / n) * n; // largest multiple of n ≤ 256 (232)
  const buf = new Uint8Array(1);
  let out = "";
  while (out.length < length) {
    crypto.getRandomValues(buf);
    if (buf[0] >= limit) continue; // reject to keep the distribution uniform
    out += INVITE_ALPHABET[buf[0] % n];
  }
  return out;
}

