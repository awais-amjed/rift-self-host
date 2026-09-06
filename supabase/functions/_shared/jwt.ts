import { createRemoteJWKSet, jwtVerify } from "npm:jose@5";

/**
 * Local (in-process) verification of a GoTrue **ES256** JWT against the stack's
 * public JWKS — so authenticated calls no longer round-trip to GoTrue on every
 * request (contrast `supabase.auth.getUser`, which does). The JWKS is fetched
 * once per warm instance and cached; `jose` auto-refetches when it encounters an
 * unknown `kid` (i.e. after a signing-key rotation).
 *
 * We verify signature + expiry + audience. Issuer is **intentionally not**
 * enforced: the token's `iss` is the external Kong URL while functions see the
 * internal `SUPABASE_URL`, so an issuer match would reject every token.
 * Signature + `aud` + `exp` is the standard sufficient set. Ban state,
 * deleted-user (auth.users delete cascades to public.users), and permissions are
 * still checked against the `users` row on every call — see `auth.ts`.
 */
const JWKS = createRemoteJWKSet(
  new URL(`${Deno.env.get("SUPABASE_URL")}/auth/v1/.well-known/jwks.json`),
);

/** Returns the caller's `auth.uid` (`sub`) if the JWT is valid, else null. */
export async function verifyJwt(token: string): Promise<string | null> {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      audience: "authenticated", // GoTrue's aud for logged-in users
    });
    return typeof payload.sub === "string" && payload.sub.length > 0
      ? payload.sub
      : null;
  } catch {
    return null;
  }
}
