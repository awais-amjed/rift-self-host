import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import { decodeJwt, importJWK, type JWK, jwtVerify } from "npm:jose@5";
import {
  generateSecrets,
  generateSigningSecrets,
  randomString,
  signApiKey,
  type SigningSecrets,
} from "./secrets.ts";

Deno.test("generated secrets are safe inside a connection URI", async () => {
  // postgres://supabase_auth_admin:PASSWORD@db:5432/postgres — one '@' or '/'
  // in the password and every service fails to reach the database, each in its
  // own way, none of them mentioning the password.
  const secrets = await generateSecrets();
  for (const value of [secrets.postgresPassword, secrets.jwtSecret]) {
    assertMatch(value, /^[A-Za-z0-9]+$/);
  }
});

Deno.test("the realtime key is exactly sixteen bytes", async () => {
  // Realtime uses it as an AES-128 key. Anything else and the container
  // crash-loops on an Elixir stacktrace.
  const secrets = await generateSecrets();
  assertEquals(secrets.realtimeEncryptionKey.length, 16);
  assertEquals(new TextEncoder().encode(secrets.realtimeEncryptionKey).length, 16);
});

Deno.test("the Phoenix secret clears its sixty-four byte floor", async () => {
  const secrets = await generateSecrets();
  assert(secrets.secretKeyBase.length >= 64);
});

Deno.test("both API keys verify against the stack's own secret", async () => {
  const secrets = await generateSecrets();
  const key = new TextEncoder().encode(secrets.jwtSecret);

  const anon = await jwtVerify(secrets.anonKey, key);
  assertEquals(anon.payload.role, "anon");
  assertEquals(anon.payload.iss, "supabase");

  const service = await jwtVerify(secrets.serviceRoleKey, key);
  assertEquals(service.payload.role, "service_role");
});

Deno.test("an API key outlives any plausible neglect", async () => {
  const secrets = await generateSecrets();
  const { exp } = decodeJwt(secrets.anonKey);
  const yearsAway = (exp! - Date.now() / 1000) / (365 * 24 * 60 * 60);
  // Baked into every client that ever joins. An expiry anyone alive today
  // would meet is a server that stops working for reasons nobody remembers.
  assert(yearsAway > 9, `expires in ${yearsAway.toFixed(1)} years`);
});

Deno.test("two runs share nothing", async () => {
  const first = await generateSecrets();
  const second = await generateSecrets();
  assert(first.jwtSecret !== second.jwtSecret);
  assert(first.postgresPassword !== second.postgresPassword);
  assert(first.anonKey !== second.anonKey);
});

Deno.test("a key signed under one secret does not verify under another", async () => {
  const mine = await signApiKey("secret-one", "anon");
  const key = new TextEncoder().encode("secret-two");
  let rejected = false;
  try {
    await jwtVerify(mine, key);
  } catch {
    rejected = true;
  }
  assert(rejected, "a key must not verify under the wrong secret");
});

Deno.test("random strings are the length asked for", () => {
  for (const length of [1, 16, 32, 64, 100]) {
    assertEquals(randomString(length).length, length);
  }
});

Deno.test("no character of the alphabet is starved or favoured", () => {
  // Rejection sampling exists so that 62 not dividing 256 does not make the
  // first 8 letters twice as likely as the rest. A modulo would show up here.
  const counts = new Map<string, number>();
  for (const character of randomString(62_000)) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  assertEquals(counts.size, 62, "every character should appear at least once");
  const frequencies = [...counts.values()];
  const lowest = Math.min(...frequencies);
  const highest = Math.max(...frequencies);
  // Expected 1000 each. A modulo bias would put the favoured characters
  // around 2x the starved ones, far outside this.
  assert(highest / lowest < 1.5, `spread ${lowest}..${highest} looks biased`);
});

Deno.test("new signing secrets keep the publishable key and replace the rest", async () => {
  const before = await generateSecrets();
  const after = await generateSigningSecrets(before.publishableKey);

  // Every member's app logs in with it. Replacing it would sign them out with
  // nothing to sign back in with.
  assertEquals(after.publishableKey, before.publishableKey);

  for (
    const name of [
      "jwtSecret",
      "secretKey",
      "anonKey",
      "serviceRoleKey",
      "anonKeyAsymmetric",
      "serviceRoleKeyAsymmetric",
    ] as const
  ) {
    assert(after[name] !== before[name], `${name} did not change`);
  }
  assert(after.signingKeys.kid !== before.signingKeys.kid);
});

/** Whether [token] verifies under [key]. */
async function verifies(token: string, key: CryptoKey | Uint8Array): Promise<boolean> {
  try {
    await jwtVerify(token, key);
    return true;
  } catch {
    return false;
  }
}

/** The public EC key a generation publishes. */
async function publicKey(secrets: SigningSecrets): Promise<CryptoKey | Uint8Array> {
  const jwk = secrets.signingKeys.verifying.keys.find((key) => key.kty === "EC");
  return await importJWK(jwk as unknown as JWK, "ES256");
}

Deno.test("a service key from the last generation does not verify against the next", async () => {
  // The whole point of rotating. Kong passes a caller's own Authorization
  // header through, so a leaked service-role JWT is refused only once nothing
  // trusts the key that signed it — replacing the opaque key alone does not
  // do it. Both flavours are checked because the stack accepts both.
  const before = await generateSecrets();
  const after = await generateSigningSecrets(before.publishableKey);
  const secret = new TextEncoder().encode(after.jwtSecret);

  assert(await verifies(after.serviceRoleKey, secret));
  assert(!(await verifies(before.serviceRoleKey, secret)));

  assert(await verifies(after.serviceRoleKeyAsymmetric, await publicKey(after)));
  assert(!(await verifies(before.serviceRoleKeyAsymmetric, await publicKey(after))));
});
