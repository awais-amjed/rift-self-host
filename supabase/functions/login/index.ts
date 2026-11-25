import "@supabase/functions-js/edge-runtime.d.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";

/**
 * Sign-in-with-Web3 (SIWS) login proxy.
 *
 * The client signs a SIWS message with its per-server Ed25519 key and posts it
 * here. We forward it to GoTrue's web3 grant server-side (the anon key lives in
 * this function's env), so the client authenticates through the normal
 * functions route without needing the server's anon key up front. Returns the
 * GoTrue session (access_token + refresh_token). See API.md.
 */
/** Set by Caddy (`templates/caddy/Caddyfile`), read by Auth. */
const CLIENT_IP_HEADER = "X-Rift-Client-IP";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { message, signature } = await req.json();
    if (!message || !signature) {
      return CustomResponse.error(
        "Missing required fields: message, signature",
        EC.MISSING_FIELDS,
      );
    }

    const url = Deno.env.get("SUPABASE_URL")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "apikey": anon,
      "Authorization": `Bearer ${anon}`,
    };
    // The address Caddy saw, passed on. Auth limits sign-in per address only
    // by this header (`GOTRUE_RATE_LIMIT_HEADER`), and this request is a new
    // one from inside the stack: without it every attempt came from nowhere,
    // and a key could be tried as fast as it could be sent. Caddy replaces
    // any copy a client sends, so what arrives here is Caddy's.
    const clientIp = req.headers.get(CLIENT_IP_HEADER);
    if (clientIp) headers[CLIENT_IP_HEADER] = clientIp;

    const res = await fetch(`${url}/auth/v1/token?grant_type=web3`, {
      method: "POST",
      headers,
      body: JSON.stringify({ chain: "solana", message, signature }),
    });

    const data = await res.json();
    if (!res.ok) {
      return CustomResponse.error(
        data.error_description ?? data.msg ?? "Login failed",
        EC.SIGNATURE_INVALID,
        data,
      );
    }

    // GoTrue session: access_token, refresh_token, expires_in, expires_at, ...
    return CustomResponse.success(data);
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});
