import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Answer central's question: was this listing token issued by an admin here?
 *
 * **Unauthenticated, and it has to be.** Central holds no session on this
 * server and never will — it is a different database with a different notion
 * of who anybody is. What makes this safe to leave open is that the token *is*
 * the credential: 256 random bits, single-use, five-minute life, and only its
 * digest stored (migration 042). Presenting one is the whole proof, and
 * guessing one is not a thing that happens.
 *
 * It answers with almost nothing on purpose. A valid token returns the server
 * id it was issued for — which the caller already named — and everything else
 * returns the same flat refusal. There is no oracle here for whether a server
 * exists, whether a token once existed, or whether it has been spent.
 *
 * Deploy with `--no-verify-jwt`, like `webhook` and for the same reason: the
 * caller cannot log in, by design.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { token } = await req.json();
    if (typeof token !== "string" || token.length !== 64) {
      return refuse();
    }

    // Burns it in the same statement that checks it, so two arrivals of one
    // token cannot both be told yes.
    const { data, error } = await supabase.rpc("redeem_listing_token", {
      p_token_hash: await sha256Hex(token),
    });

    // A database error and an unknown token answer alike. Which it was is
    // this server's business, and telling central would tell anyone who can
    // reach this endpoint.
    if (error || !data) return refuse();

    return CustomResponse.success({ verified: true, server_id: data });
  } catch (_err) {
    return refuse();
  }
});

/**
 * The single answer for every failure.
 *
 * Deliberately not `CustomResponse.error` with a reason: expired, already
 * spent, never existed and malformed are four different facts about this
 * server, and an endpoint anybody may call should not distinguish them.
 */
function refuse(): Response {
  return CustomResponse.error(
    "That listing token is not valid",
    EC.PERMISSION_DENIED,
  );
}

/** SHA-256, hex — the form the table stores. */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
