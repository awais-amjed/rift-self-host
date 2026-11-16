/**
 * Central's pass for joining through a link that needs a Rift account.
 *
 * A server cannot tell a Rift account from an identity made a moment ago, so
 * central vouches: for a signed-in account with a confirmed email, its
 * `server_pass` function signs a pass naming this server, the one identity
 * that will join with it, five minutes of life, and a **tag** — the same for
 * that account on this server, different on every other, and no email in it.
 * `register` checks it here and hands the tag to `register_user`.
 *
 * The pass is `b64url(payload).b64url(signature)`: the payload is JSON, and
 * the Ed25519 signature covers exactly those bytes, so nothing is parsed
 * before it is known to be central's. Naming the identity is what makes a
 * pass useless to anybody who copies it: `register` compares it with the key
 * the caller actually signed in with ([web3KeyMatches]), not one they typed.
 *
 * The server's address must be this server's own public one
 * (`SUPABASE_PUBLIC_URL`), compared as an origin. Central makes the tag from
 * the address it is given, so a pass naming any other address carries a tag
 * nobody has banned: accepting one would be a way round every ban. The app
 * asks central with the address `resolve_invite` names for that reason.
 */

/** Central's public key for passes: 32 raw bytes, base64. Empty until the
 *  key exists; with none, every pass is refused. `RIFT_CENTRAL_PASS_KEY`
 *  overrides it, for a test stack or a key change. */
export const CENTRAL_PASS_PUBLIC_KEY = "";

function centralKeyFromEnv(): string {
  try {
    return Deno.env.get("RIFT_CENTRAL_PASS_KEY") || CENTRAL_PASS_PUBLIC_KEY;
  } catch {
    return CENTRAL_PASS_PUBLIC_KEY;
  }
}

function fromB64(text: string, url: boolean): Uint8Array<ArrayBuffer> {
  let s = url ? text.replace(/-/g, "+").replace(/_/g, "/") : text;
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

/**
 * The pass's tag, if central signed it for [serverId] and the identity whose
 * key is [publicKey] (base64, as `register` receives it) and it has not
 * expired; otherwise null. Never throws.
 */
export async function verifyServerPass(
  pass: string,
  opts: {
    serverId: string;
    publicKey: string;
    publicUrl: string;
    now?: number;
    centralKey?: string;
  },
): Promise<{ tag: string } | null> {
  try {
    const keyText = opts.centralKey ?? centralKeyFromEnv();
    if (!keyText) return null;
    const parts = pass.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
    const payload = fromB64(parts[0], true);
    const signature = fromB64(parts[1], true);
    const key = await crypto.subtle.importKey(
      "raw",
      fromB64(keyText, false),
      "Ed25519",
      false,
      ["verify"],
    );
    if (!(await crypto.subtle.verify("Ed25519", key, signature, payload))) return null;

    const body = JSON.parse(new TextDecoder().decode(payload));
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (body?.v !== 1) return null;
    if (typeof body.exp !== "number" || body.exp < now) return null;
    if (body.server_id !== opts.serverId) return null;
    if (body.public_key !== opts.publicKey) return null;
    if (!opts.publicUrl || typeof body.supabase_url !== "string") return null;
    if (new URL(body.supabase_url).origin !== new URL(opts.publicUrl).origin) return null;
    if (typeof body.tag !== "string" || !body.tag) return null;
    return { tag: body.tag };
  } catch {
    return null;
  }
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function fromBase58(text: string): Uint8Array | null {
  let n = 0n;
  for (const c of text) {
    const digit = BASE58.indexOf(c);
    if (digit < 0) return null;
    n = n * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of text) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/**
 * Whether the caller's sign-in, GoTrue's `web3:solana:<base58 address>`
 * subject, is the identity whose key is [publicKey] (base64). A Solana
 * address is the Ed25519 public key itself.
 */
export function web3KeyMatches(subject: string, publicKey: string): boolean {
  try {
    const prefix = "web3:solana:";
    if (!subject.startsWith(prefix)) return false;
    const signedIn = fromBase58(subject.slice(prefix.length));
    const claimed = fromB64(publicKey, false);
    if (!signedIn || signedIn.length !== 32 || claimed.length !== 32) return false;
    return signedIn.every((b, i) => b === claimed[i]);
  } catch {
    return false;
  }
}
