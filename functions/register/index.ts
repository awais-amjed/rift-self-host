import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
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
 * (see auth.md / migration 007). No token is issued — the client already holds
 * the JWT.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // 0. Identify the caller from their SIWS JWT. authenticateToken can't be
    //    used here — there's no users row yet — so verify the JWT directly.
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    const { data: userData, error: authError } = await supabase.auth.getUser(token);
    if (authError || !userData?.user) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID, authError);
    }
    const authUid = userData.user.id;

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

    // 1. Already registered? (idempotent-ish: same identity re-calling register)
    const { data: existingSelf } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.id, authUid)
      .maybeSingle();
    if (existingSelf) {
      return CustomResponse.error("Already registered on this server", EC.IDENTITY_TAKEN);
    }

    // 2. Atomically claim one use of the invite (race-safe).
    const { data: claimData, error: claimError } = await supabase
      .rpc("claim_invite", { p_invite_code: invite_code });

    if (claimError) {
      return CustomResponse.error("Error processing invite", EC.DB_ERROR, claimError);
    }

    const claim = claimData as Record<string, any>;
    if (claim.reason === "not_found") {
      return CustomResponse.error("Invalid invite code", EC.INVITE_INVALID);
    }
    if (claim.reason === "expired") {
      return CustomResponse.error("Invite code has expired", EC.INVITE_EXPIRED);
    }
    if (claim.reason === "exhausted") {
      return CustomResponse.error("Invite code has reached its maximum uses", EC.INVITE_EXHAUSTED);
    }

    const server_id = claim[DBSchema.invites.serverId] as string;

    // 3. Duplicate identity checks — scoped to this server.
    const { data: existingByKey } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.publicKey, public_key)
      .maybeSingle();
    if (existingByKey) {
      return CustomResponse.error("This identity is already registered on this server", EC.IDENTITY_TAKEN);
    }

    const { data: existingByStableId } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.serverId, server_id)
      .eq(DBSchema.users.stableId, stable_id)
      .maybeSingle();
    if (existingByStableId) {
      return CustomResponse.error("This identity is already registered on this server", EC.IDENTITY_TAKEN);
    }

    // 4. Username uniqueness.
    const { data: existingUser } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.username, username)
      .maybeSingle();
    if (existingUser) {
      return CustomResponse.error("Username already taken", EC.USERNAME_TAKEN);
    }

    // 5. Insert the profile bound to the GoTrue identity (users.id = auth.uid()).
    const { error: insertError } = await supabase
      .from(DBSchema.users.tableName)
      .insert({
        [DBSchema.users.id]:              authUid,
        [DBSchema.users.serverId]:        server_id,
        [DBSchema.users.username]:        username,
        [DBSchema.users.displayName]:     display_name,
        [DBSchema.users.publicKey]:       public_key,
        [DBSchema.users.stableId]:        stable_id,
        [DBSchema.users.isServerAdmin]:   claim[DBSchema.invites.isServerAdmin],
        [DBSchema.users.isChannelManager]: claim[DBSchema.invites.isChannelManager],
        // Baseline: every member may create (plain) invites, Discord-style.
        [DBSchema.users.canCreateTokens]: true,
      });

    if (insertError) {
      return CustomResponse.error("Error creating user", EC.DB_ERROR, insertError);
    }

    // 6. Return full server context (no token — the client holds the JWT).
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
