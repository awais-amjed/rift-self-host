import { SupabaseClient } from "@supabase/supabase-js";
import DBSchema from "./schema.ts";
import { CustomResponse } from "./response.ts";
import * as EC from "./error_codes.ts";

/**
 * Fetch full server context: server details, user profile, and channels.
 *
 * Permissions are read directly from the **users** table. Sessions are GoTrue
 * JWTs held by the client (SIWS), so no token is returned here.
 *
 * Returns the assembled response object matching the standard shape used by
 * register and get_server_details. Returns a Response on error.
 */
export async function fetchServerContext(
  supabase: SupabaseClient,
  opts: {
    serverId: string;
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

  // Fetch channels — the ones this caller may see, and no others.
  //
  // This runs on the service role, so `channels_select` does not: the filter
  // that policy applies (`NOT is_private OR app.in_channel(...)`) has to be
  // applied here by hand or not at all. It was not, and the only caller is
  // `register` — so the first thing a brand-new member received was the id and
  // name of every private channel on the server, which is the one thing a
  // private channel is for. `get_server_details`, which answers the same
  // question on every later refresh, runs as the caller and was always right;
  // this is the join path catching up with it.
  //
  // `visible_channels` is the same answer the policy gives, asked of the
  // database rather than reimplemented here.
  const { data: visibleData } = await supabase.rpc("visible_channels", {
    p_user: opts.userId,
  });
  const visibleIds = ((visibleData ?? []) as Record<string, any>[])
    .map((c) => c.channel_id as string);

  let channels: Record<string, unknown>[] = [];
  if (visibleIds.length > 0) {
    const { data: channelsData } = await supabase
      .from(DBSchema.channels.tableName)
      .select(
        `${DBSchema.channels.id}, ${DBSchema.channels.name}, ${DBSchema.channels.channelType}`,
      )
      .eq(DBSchema.channels.serverId, opts.serverId)
      .in(DBSchema.channels.id, visibleIds)
      // As `get_server_details` lists them. Unordered, a member who had just
      // joined saw creation order until the next refresh, so their sidebar
      // differed from everyone else's.
      .order(DBSchema.channels.position)
      .order(DBSchema.channels.name);

    channels = (channelsData || []).map((c: Record<string, any>) => ({
      id: c[DBSchema.channels.id],
      name: c[DBSchema.channels.name],
      channel_type: c[DBSchema.channels.channelType],
    }));
  }

  return {
    server_id: opts.serverId,
    name: server[DBSchema.servers.name],
    icon_url: server[DBSchema.servers.iconUrl],
    livekit_url: server[DBSchema.servers.livekitUrl],
    supabase_key: Deno.env.get("SUPABASE_ANON_KEY"),
    user,
    channels,
  };
}
