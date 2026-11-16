import { assertEquals } from "jsr:@std/assert@1";
import { verifyServerPass, web3KeyMatches } from "./server_pass.ts";

// A pass as central makes one (`server_pass` in rift-central): the payload's
// JSON bytes, signed with Ed25519, each half base64url.
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_")
    .replace(/=+$/, "");
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
const centralKey = b64(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));

const serverId = "cccc0000-0000-4000-8000-000000000001";
const publicKey = b64(new Uint8Array(32).fill(7));
const now = 1_800_000_000;

async function makePass(fields: Record<string, unknown>, tamper = false): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify({
    v: 1,
    server_id: serverId,
    supabase_url: "https://rift.example",
    public_key: publicKey,
    tag: "tag-1",
    exp: now + 300,
    ...fields,
  }));
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, payload));
  if (tamper) payload[payload.length - 2] ^= 1;
  return `${b64url(payload)}.${b64url(signature)}`;
}

const publicUrl = "https://rift.example";
const check = (pass: string, at = now) =>
  verifyServerPass(pass, { serverId, publicKey, publicUrl, now: at, centralKey });

Deno.test("a pass central signed for this server and identity gives its tag", async () => {
  assertEquals(await check(await makePass({})), { tag: "tag-1" });
});

Deno.test("an expired pass is refused", async () => {
  assertEquals(await check(await makePass({}), now + 301), null);
});

Deno.test("a pass for another server is refused", async () => {
  assertEquals(await check(await makePass({ server_id: "dddd0000-0000-4000-8000-000000000001" })), null);
});

Deno.test("a pass for another identity is refused", async () => {
  assertEquals(await check(await makePass({ public_key: b64(new Uint8Array(32).fill(8)) })), null);
});

Deno.test("a pass changed after signing is refused", async () => {
  assertEquals(await check(await makePass({}, true)), null);
});

Deno.test("a pass signed by somebody else is refused", async () => {
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  const otherKey = b64(new Uint8Array(await crypto.subtle.exportKey("raw", other.publicKey)));
  assertEquals(
    await verifyServerPass(await makePass({}), { serverId, publicKey, publicUrl, now, centralKey: otherKey }),
    null,
  );
});

Deno.test("garbage is refused, never thrown", async () => {
  for (const junk of ["", "x", "a.b", "....", "eyJ2IjoxfQ.AAAA"]) {
    assertEquals(await check(junk), null);
  }
});

Deno.test("with no central key set, every pass is refused", async () => {
  assertEquals(
    await verifyServerPass(await makePass({}), { serverId, publicKey, publicUrl, now, centralKey: "" }),
    null,
  );
});

// The tag is made from the address in the pass, so an address the server
// does not answer to is a fresh tag — a way round every ban — unless the
// server refuses it.
Deno.test("a pass for another address of the same server id is refused", async () => {
  assertEquals(await check(await makePass({ supabase_url: "https://anything.example" })), null);
});

Deno.test("the address is compared as an origin", async () => {
  assertEquals(await check(await makePass({ supabase_url: "https://Rift.example/" })), { tag: "tag-1" });
});

Deno.test("a server that does not know its own address refuses every pass", async () => {
  assertEquals(
    await verifyServerPass(await makePass({}), { serverId, publicKey, publicUrl: "", now, centralKey }),
    null,
  );
});

// GoTrue names a Solana sign-in `web3:solana:<base58 address>`, and the
// address is the identity's Ed25519 key.
const base58 = (bytes: Uint8Array) => {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
};

Deno.test("the signed-in identity's key matches the one the pass names", () => {
  const key = new Uint8Array(32).fill(7);
  assertEquals(web3KeyMatches(`web3:solana:${base58(key)}`, publicKey), true);
});

Deno.test("another identity's key, or no web3 sign-in, does not match", () => {
  const other = new Uint8Array(32).fill(8);
  assertEquals(web3KeyMatches(`web3:solana:${base58(other)}`, publicKey), false);
  assertEquals(web3KeyMatches("web3:solana:", publicKey), false);
  assertEquals(web3KeyMatches("email:someone", publicKey), false);
  assertEquals(web3KeyMatches(`web3:solana:${base58(new Uint8Array([0, ...key32()]))}`, publicKey), false);
});

function key32() { return new Uint8Array(32).fill(7); }
