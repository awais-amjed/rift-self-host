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
 * pass useless to anybody who copies it: they would have to sign in as that
 * key. The server's address is in the pass (it went into the tag) but is not
 * compared with this server's own, which a server reached by more than one
 * address would fail.
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
  opts: { serverId: string; publicKey: string; now?: number; centralKey?: string },
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
    if (typeof body.tag !== "string" || !body.tag) return null;
    return { tag: body.tag };
  } catch {
    return null;
  }
}
