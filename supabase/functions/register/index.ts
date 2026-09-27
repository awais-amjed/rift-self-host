import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { fetchServerContext } from "../_shared/server_context.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Create this server's profile row for an already-authenticated caller.
 *
 * The client first authenticates via Sign-in-with-Web3 (SIWS), which yields a
 * GoTrue JWT for a fresh `auth.users` row keyed by the caller's Ed25519 key.
 * register then binds a `users` profile to that identity: `users.id = auth.uid()`
 * (see API.md). No token is issued — the client already holds
 * the JWT.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // 0. Identify the caller from their SIWS JWT. authenticateToken can't be
    //    used here — there's no users row yet — so verify the JWT directly
    //    (locally against the JWKS, same as authenticateToken).
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    const authUid = await verifyJwt(token);
    if (!authUid) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    const { invite_code, public_key, stable_id, username, display_name } =
      await req.json();

    if (!invite_code || !public_key || !stable_id || !username || !display_name) {
      return CustomResponse.error(
        "Missing required fields: invite_code, public_key, stable_id, username, display_name",
        EC.MISSING_FIELDS,
      );
    }

    // Validate public_key: base64 of exactly 32 bytes (Ed25519).
    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = Uint8Array.from(atob(public_key), (c) => c.charCodeAt(0));
    } catch {
      return CustomResponse.error("Invalid public_key: not valid base64", EC.INVALID_PUBLIC_KEY);
    }
    if (publicKeyBytes.length !== 32) {
      return CustomResponse.error(
        `Invalid public_key: expected 32 bytes, got ${publicKeyBytes.length}`,
        EC.INVALID_PUBLIC_KEY,
      );
    }

    // Validate stable_id: base64 of exactly 32 bytes (HMAC-SHA256).
    let stableIdBytes: Uint8Array;
    try {
      stableIdBytes = Uint8Array.from(atob(stable_id), (c) => c.charCodeAt(0));
    } catch {
      return CustomResponse.error("Invalid stable_id: not valid base64", EC.INVALID_STABLE_ID);
    }
    if (stableIdBytes.length !== 32) {
      return CustomResponse.error(
        `Invalid stable_id: expected 32 bytes, got ${stableIdBytes.length}`,
        EC.INVALID_STABLE_ID,
      );
    }

    // Claim the invite + create the profile atomically. The
    // invite is only consumed once every check passes, so a rejected register
    // (e.g. username taken) never burns an invite use.
    const { data: regData, error: regError } = await supabase.rpc("register_user", {
      p_invite_code:  invite_code,
      p_user_id:      authUid,
      p_public_key:   public_key,
      p_stable_id:    stable_id,
      p_username:     username,
      p_display_name: display_name,
    });

    if (regError) {
      return CustomResponse.error("Error creating user", EC.DB_ERROR, regError);
    }

    const reg = regData as Record<string, any>;
    switch (reg.reason) {
      case "ok":
        break;
      case "not_found":
        return CustomResponse.error("Invalid invite code", EC.INVITE_INVALID);
      case "expired":
        return CustomResponse.error("Invite code has expired", EC.INVITE_EXPIRED);
      case "exhausted":
        return CustomResponse.error("Invite code has reached its maximum uses", EC.INVITE_EXHAUSTED);
      case "already_registered":
        return CustomResponse.error("Already registered on this server", EC.IDENTITY_TAKEN);
      case "identity_taken":
        return CustomResponse.error("This identity is already registered on this server", EC.IDENTITY_TAKEN);
      case "username_taken":
        return CustomResponse.error("Username already taken", EC.USERNAME_TAKEN);
      case "username_invalid":
        return CustomResponse.error(
          "Usernames are 2\u201332 characters: letters, numbers, underscore, dot or hyphen \u2014 no spaces",
          EC.USERNAME_INVALID,
        );
      // Last, like the check itself: everything above is about the caller,
      // and this is about the server. It is also the only refusal here a
      // valid invite can still produce, so it says what to do about it.
      case "server_full":
        return CustomResponse.error(
          "This server is full — ask an admin to make room or raise the limit",
          EC.SERVER_FULL,
        );
      default:
        return CustomResponse.error("Error creating user", EC.DB_ERROR, reg);
    }

    const server_id = reg[DBSchema.invites.serverId] as string;

    // Return full server context (no token — the client holds the JWT).
    const context = await fetchServerContext(supabase, {
      serverId: server_id,
      userId: authUid,
    });
    if (context instanceof Response) return context;

    return CustomResponse.success(context);
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
