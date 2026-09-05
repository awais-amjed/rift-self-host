/**
 * The keypair GoTrue signs sessions with.
 *
 * Rift's edge functions verify a caller's JWT **locally, against the stack's
 * public JWKS** rather than round-tripping to GoTrue on every request
 * (`_shared/jwt.ts`). That only works if sessions are signed with an
 * asymmetric key whose public half GoTrue publishes at
 * `/auth/v1/.well-known/jwks.json`.
 *
 * A stack configured with `GOTRUE_JWT_SECRET` alone signs HS256 and publishes
 * `{"keys":[]}` — correctly, since serving a symmetric secret from a public
 * endpoint would hand every reader the ability to mint sessions. Verification
 * then fails for every authenticated call, with `token_invalid`, and nobody
 * can register or join. The stack looks healthy throughout: it is only the
 * *authenticated* half of the API that is dead, so a smoke test that stops at
 * `resolve_invite` sails past it.
 *
 * So the EC key is not optional and never has been.
 */
import { encodeBase64Url } from "jsr:@std/encoding@1/base64url";

/** A JSON Web Key, as GoTrue and the services exchange them. */
export type Jwk = Record<string, unknown>;

/** Both halves, in the shapes the stack's variables want. */
export interface SigningKeys {
  /** `JWT_KEYS` — a bare array: EC private key first, then the legacy secret. */
  signing: Jwk[];
  /** `JWT_JWKS` — `{keys: [...]}`: EC public key, then the legacy secret. */
  verifying: { keys: Jwk[] };
  /** The key id shared by both halves. */
  kid: string;
}

/**
 * The legacy HS256 secret, expressed as a JWK.
 *
 * Carried alongside the EC key so tokens signed before a stack gained an
 * asymmetric key still verify. Deliberately has **no `key_ops`**: that is what
 * stops GoTrue choosing it to sign with, which would put the stack straight
 * back into the failure above.
 */
function symmetricJwk(jwtSecret: string): Jwk {
  return {
    kty: "oct",
    alg: "HS256",
    k: encodeBase64Url(new TextEncoder().encode(jwtSecret)),
  };
}

/**
 * Generate a P-256 keypair and express it both ways.
 *
 * ES256 rather than RS256 because it is what GoTrue defaults to and what the
 * app's `_shared/jwt.ts` names explicitly; the keys are also an order of
 * magnitude smaller, which matters when they travel as environment variables.
 */
export async function generateSigningKeys(jwtSecret: string): Promise<SigningKeys> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const kid = crypto.randomUUID();
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);

  const common = { alg: "ES256", use: "sig", kid, ext: true };
  const legacy = symmetricJwk(jwtSecret);

  return {
    kid,
    signing: [{ ...priv, ...common, key_ops: ["sign", "verify"] }, legacy],
    verifying: {
      keys: [
        // The private component is dropped explicitly rather than by omission:
        // this object is published to anyone who asks for the JWKS.
        { ...pub, ...common, key_ops: ["verify"], d: undefined },
        legacy,
      ].map((key) => JSON.parse(JSON.stringify(key)) as Jwk),
    },
  };
}

/** Import the private half for signing. */
export async function importSigningKey(keys: SigningKeys): Promise<CryptoKey> {
  const jwk = keys.signing.find((key) => key.kty === "EC");
  if (!jwk) throw new Error("No EC key to sign with");

  return await crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["sign"] } as JsonWebKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}
