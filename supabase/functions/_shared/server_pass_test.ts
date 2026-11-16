import { assertEquals } from "jsr:@std/assert@1";
import { verifyServerPass } from "./server_pass.ts";

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

const check = (pass: string, at = now) =>
  verifyServerPass(pass, { serverId, publicKey, now: at, centralKey });

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
    await verifyServerPass(await makePass({}), { serverId, publicKey, now, centralKey: otherKey }),
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
    await verifyServerPass(await makePass({}), { serverId, publicKey, now, centralKey: "" }),
    null,
  );
});
