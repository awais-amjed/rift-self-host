import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Discord-style permission management: server admins set per-user flags
 * after members join with baseline permissions (invites carry none).
 *
 * Callers cannot edit their own permissions — this prevents the last
 * admin from accidentally demoting themselves and orphaning the server.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { user_id, is_server_admin, is_channel_manager, can_create_tokens } =
      await req.json();
    const token = extractBearerToken(req);

    if (
      !user_id ||
      (is_server_admin === undefined &&
        is_channel_manager === undefined &&
        can_create_tokens === undefined)
    ) {
      return CustomResponse.error(
        "Missing required fields: user_id and at least one permission flag",
        EC.MISSING_FIELDS,
      );
    }

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!auth.isServerAdmin) {
      return CustomResponse.error(
        "Unauthorized: Only server admins can manage permissions",
        EC.PERMISSION_DENIED,
      );
    }

    if (user_id === auth.userId) {
      return CustomResponse.error(
        "You cannot change your own permissions",
        EC.PERMISSION_DENIED,
      );
    }

    // Target must exist on this server.
    const { data: targetData, error: targetError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}`)
      .eq(DBSchema.users.id, user_id)
      .eq(DBSchema.users.serverId, auth.serverId)
      .single();

    if (targetError || !targetData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, targetError);
    }

    const update: Record<string, boolean> = {};
    if (is_server_admin !== undefined) {
      update[DBSchema.users.isServerAdmin] = is_server_admin === true;
    }
    if (is_channel_manager !== undefined) {
      update[DBSchema.users.isChannelManager] = is_channel_manager === true;
    }
    if (can_create_tokens !== undefined) {
      update[DBSchema.users.canCreateTokens] = can_create_tokens === true;
    }

    const { data: updated, error: updateError } = await supabase
      .from(DBSchema.users.tableName)
      .update(update)
      .eq(DBSchema.users.id, user_id)
      .select(
        `${DBSchema.users.isServerAdmin}, ${DBSchema.users.isChannelManager}, ${DBSchema.users.canCreateTokens}`,
      )
      .single();

    if (updateError || !updated) {
      return CustomResponse.error("Error updating permissions", EC.DB_ERROR, updateError);
    }

    const u = updated as Record<string, any>;
    return CustomResponse.success({
      user_id,
      permissions: {
        is_server_admin: u[DBSchema.users.isServerAdmin],
        is_channel_manager: u[DBSchema.users.isChannelManager],
        can_create_tokens: u[DBSchema.users.canCreateTokens],
      },
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
