import { SupabaseClient } from "@supabase/supabase-js";
import DBSchema from "./schema.ts";
import { CustomResponse } from "./response.ts";
import * as EC from "./error_codes.ts";

/**
 * Fetch full server context: server details, user profile, and channels.
 *
 * Permissions are read directly from the **users** table.
 *
 * Returns the assembled response object matching the standard shape used by
 * verify_challenge, register, and get_server_details.
 * Returns a Response on error.
 */
export async function fetchServerContext(
  supabase: SupabaseClient,
  opts: {
    serverId: string;
    tokenValue: string;
    userId: string;
  },
): Promise<Record<string, any> | Response> {
  // Fetch server details
  const { data: serverData, error: serverError } = await supabase
    .from(DBSchema.servers.tableName)
    .select(
      `${DBSchema.servers.name}, ${DBSchema.servers.iconUrl}, ${DBSchema.servers.livekitUrl}`,
    )
    .eq(DBSchema.servers.id, opts.serverId)
    .single();

  if (serverError || !serverData) {
    return CustomResponse.error(
      `Server not found (fetchServerContext, serverId="${opts.serverId}"): ${JSON.stringify(serverError)}`,
      EC.SERVER_NOT_FOUND,
      serverError,
    );
  }

  const server = serverData as Record<string, any>;

  // Fetch user profile + permissions
  const { data: userData } = await supabase
    .from(DBSchema.users.tableName)
    .select(
      `${DBSchema.users.id}, ${DBSchema.users.username}, ${DBSchema.users.displayName}, ${DBSchema.users.isServerAdmin}, ${DBSchema.users.isChannelManager}, ${DBSchema.users.canCreateTokens}, ${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}`,
    )
    .eq(DBSchema.users.id, opts.userId)
    .single();

  let user: Record<string, any> | null = null;
  if (userData) {
    const u = userData as Record<string, any>;
    user = {
      id: u[DBSchema.users.id],
      username: u[DBSchema.users.username],
      display_name: u[DBSchema.users.displayName],
      permissions: {
        is_server_admin: u[DBSchema.users.isServerAdmin],
        is_channel_manager: u[DBSchema.users.isChannelManager],
        can_create_tokens: u[DBSchema.users.canCreateTokens],
      },
      is_muted: u[DBSchema.users.isMuted],
      is_deafened: u[DBSchema.users.isDeafened],
    };
  }

  // Fetch channels
  const { data: channelsData } = await supabase
    .from(DBSchema.channels.tableName)
    .select(
      `${DBSchema.channels.id}, ${DBSchema.channels.name}, ${DBSchema.channels.channelType}`,
    )
    .eq(DBSchema.channels.serverId, opts.serverId);

  const channels = (channelsData || []).map((c: Record<string, any>) => ({
    id: c[DBSchema.channels.id],
    name: c[DBSchema.channels.name],
    channel_type: c[DBSchema.channels.channelType],
  }));

  return {
    token: opts.tokenValue,
    server_id: opts.serverId,
    name: server[DBSchema.servers.name],
    icon_url: server[DBSchema.servers.iconUrl],
    livekit_url: server[DBSchema.servers.livekitUrl],
    supabase_key: Deno.env.get("SUPABASE_ANON_KEY"),
    user,
    channels,
  };
}
