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

