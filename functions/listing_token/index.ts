import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * A one-time proof that an admin of this server asked for it to be listed.
 *
 * Central owns the public directory and cannot tell who administers a server
 * here — it has never heard of this database, and the two identities are
 * unrelated: a member signs in here with a key derived on their device, and to
 * central with a Rift account. So central asks this server instead, and this
 * is where the answer starts.
 *
 * The token is returned to the admin's client, which hands it to central;
 * central presents it back here through `verify_listing_token`. That round
 * trip is what binds a listing to a domain, because only whoever controls this
 * domain can answer for it.
 *
 * Only the digest is stored (migration 042). The token itself exists in this
 * response, in the client's memory, and in central's request — never at rest.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;
    if (!auth.isServerAdmin) {
      return CustomResponse.error(
        "Only a server admin can list this server publicly",
        EC.PERMISSION_DENIED,
      );
    }

    // 256 bits. This is the whole secret — it is presented by a caller with no
    // session at all, so it has to be unguessable on its own.
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const token = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");

    // The member id goes in explicitly: this client holds the service key, so
    // there is no session inside the function for auth.uid() to read.
    const { data, error } = await supabase.rpc("issue_listing_token", {
      p_user_id: auth.userId,
      p_server_id: auth.serverId,
      p_token_hash: await sha256Hex(token),
    });
    if (error) {
      return CustomResponse.error("Could not issue a listing token", EC.DB_ERROR, error);
    }

    return CustomResponse.success({
      token,
      server_id: auth.serverId,
      expires_at: data,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/** SHA-256, hex. What the table holds instead of the token. */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
