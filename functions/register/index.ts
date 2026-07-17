import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { generateSecureToken } from "../_shared/token_utils.ts";
import { fetchServerContext } from "../_shared/server_context.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { invite_code, public_key, stable_id, username, display_name } =
      await req.json();

    if (!invite_code || !public_key || !stable_id || !username || !display_name) {
      return CustomResponse.error(
        "Missing required fields: invite_code, public_key, stable_id, username, display_name",
        EC.MISSING_FIELDS,
      );
    }

    // Validate public_key: must be valid base64 encoding of exactly 32 bytes (Ed25519)
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

    // Validate stable_id: must be valid base64 encoding of exactly 32 bytes (HMAC-SHA256)
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

    // 1. Atomically claim one use of the invite (race-safe)
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

    // 2. Check for duplicate identity — scoped to this server only
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

    // 3. Check username uniqueness
    const { data: existingUser } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.username, username)
      .maybeSingle();

    if (existingUser) {
      return CustomResponse.error("Username already taken", EC.USERNAME_TAKEN);
    }

    // 4. Generate auth token and insert user + token atomically
    const authToken = generateSecureToken();
    const tokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

    // 5. Insert user + token atomically — rolls back both if either fails
    const { data: createData, error: createError } = await supabase.rpc(
      "create_user_with_token",
      {
        p_server_id:          server_id,
        p_username:           username,
        p_display_name:       display_name,
        p_public_key:         public_key,
        p_stable_id:          stable_id,
        p_is_server_admin:    claim[DBSchema.invites.isServerAdmin],
        p_is_channel_manager: claim[DBSchema.invites.isChannelManager],
        // Baseline: every member may create (plain) invites, Discord-style.
        // Admins can revoke this per-user via set_user_permissions.
        p_can_create_tokens:  true,
        p_auth_token:         authToken,
        p_token_expires_at:   tokenExpiresAt,
      },
    );

    if (createError) {
      return CustomResponse.error("Error creating user", EC.DB_ERROR, createError);
    }

    const user_id = (createData as Record<string, any>).user_id as string;

    // 6. Return full server context
    const context = await fetchServerContext(supabase, {
      serverId: server_id,
      tokenValue: authToken,
      userId: user_id,
    });

    if (context instanceof Response) return context;

    return CustomResponse.success(context);
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
