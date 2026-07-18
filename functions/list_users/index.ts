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
 * Member list for the server — visible to every member (like Discord's
 * member sidebar). Includes permissions and moderation state so the
 * members dialog can render badges; mutating any of it stays admin-gated
 * in set_user_permissions / moderate_user.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const { data, error } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.username}, ${DBSchema.users.displayName}, ` +
          `${DBSchema.users.createdAt}, ${DBSchema.users.isServerAdmin}, ` +
          `${DBSchema.users.isChannelManager}, ${DBSchema.users.canCreateTokens}, ` +
          `${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}, ${DBSchema.users.isBanned}, ` +
          `${DBSchema.users.chatPublicKey}`,
      )
      .eq(DBSchema.users.serverId, auth.serverId)
      .order(DBSchema.users.createdAt, { ascending: true });

    if (error) {
      return CustomResponse.error("Error listing users", EC.DB_ERROR, error);
    }

    const users = (data ?? []).map((row: Record<string, any>) => ({
      id: row[DBSchema.users.id],
      username: row[DBSchema.users.username],
      display_name: row[DBSchema.users.displayName],
      created_at: row[DBSchema.users.createdAt],
      permissions: {
        is_server_admin: row[DBSchema.users.isServerAdmin],
        is_channel_manager: row[DBSchema.users.isChannelManager],
        can_create_tokens: row[DBSchema.users.canCreateTokens],
      },
      is_muted: row[DBSchema.users.isMuted],
      is_deafened: row[DBSchema.users.isDeafened],
      is_banned: row[DBSchema.users.isBanned],
      // X25519 chat key (null until published) — needed to start a DM.
      chat_public_key: row[DBSchema.users.chatPublicKey],
    }));

    return CustomResponse.success({ users });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
