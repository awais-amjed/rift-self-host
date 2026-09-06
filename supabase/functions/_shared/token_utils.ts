// Base58 alphabet (Bitcoin's) — omits 0/O/I/l so codes are easy to read and
// retype. An invite code goes in a link somebody pastes, and often reads out
// loud, so short and legible is worth more than length.
const INVITE_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Generates a short, human-friendly invite code (default 10 base58 chars ≈
 * 58 bits of entropy). Validated by database lookup rather than by a
 * signature, so unpredictability is the only requirement; single-use and
 * expiry are what keep a code this short safe. Uses rejection sampling to
 * avoid modulo bias.
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

