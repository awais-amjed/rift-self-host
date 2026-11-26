import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServices } from "../_shared/livekit.ts";
import { connectionsOutside, readCallRights, reconcileConnections } from "../_shared/call_rights.ts";

/**
 * Bring this server's running calls up to date with its roles.
 *
 * A role is given, taken or edited straight through the database
 * (`member_roles`, `roles`), and a channel's role access through
 * `set_channel_role_access`, and none of them can reach LiveKit. A call is
 * checked when somebody joins it, never again, so a member whose role stopped
 * letting them see a private channel went on hearing its call, and one whose
 * role lost `SPEAK` went on talking, until they hung up. The app calls this
 * after such a write. For everyone in every call, or in [channel_id]'s alone:
 *
 *   * every connection of anybody who may no longer be in the call
 *     (`channel_joinable_by`, as `get_channel_token` asks) is removed, as
 *     `change_channel_members` does;
 *   * everybody else's microphone and soundboard are set as the channel now
 *     has them (`reconcileConnections`, as `set_channel_override` does).
 *
 * `CONNECT` is not asked: it is a question for the door, and nobody is put out
 * of a call they are already in for it (API.md).
 *
 * It only ever enforces what the database already says, so the gate is about
 * cost, not trust: for one channel, managing it; for the whole server, an
 * administrator or a holder of `MANAGE_ROLES`, who are the people who can
 * have changed anything it would act on.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const body = await req.json().catch(() => ({}));
    const channelId = typeof body?.channel_id === "string" ? body.channel_id : null;
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (channelId) {
      const { data: manages, error } = await supabase.rpc("channel_manageable_by", {
        p_channel: channelId,
        p_user: auth.userId,
      });
      if (error) return CustomResponse.error("Error reading channel access", EC.DB_ERROR, error);
      if (manages !== true) return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    } else if (!auth.isServerAdmin) {
      const { data: mayRole, error } = await supabase.rpc("user_has_permission", {
        p_user: auth.userId,
        p_name: "MANAGE_ROLES",
      });
      if (error) return CustomResponse.error("Error reading permissions", EC.DB_ERROR, error);
      if (mayRole !== true) {
        return CustomResponse.error("Not allowed to refresh calls", EC.PERMISSION_DENIED);
      }
    }

    const { data: channels, error: channelsError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .eq(DBSchema.channels.channelType, "voice");
    if (channelsError) {
      return CustomResponse.error("Error reading channels", EC.DB_ERROR, channelsError);
    }
    const voiceIds = ((channels ?? []) as Record<string, any>[])
      .map((c) => c[DBSchema.channels.id] as string)
      .filter((id) => channelId === null || id === channelId);
    if (voiceIds.length === 0) {
      return CustomResponse.success({ connections_removed: 0, connections_updated: 0 });
    }

    const services = await livekitRoomServices(supabase, auth.serverId);
    if (services.length === 0) {
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }

    // Every node, and every room on it: a call split across two is two
    // rooms to bring up to date, not one.
    let removed = 0;
    let updated = 0;
    let unreachable = false;
    await Promise.all(services.map(async ({ service }) => {
      let rooms;
      try {
        rooms = await service.listRooms(voiceIds);
      } catch (err) {
        console.error("[refresh_calls] rooms", err);
        unreachable = true;
        return;
      }
      await Promise.all(rooms.map(async (room) => {
        try {
          const connections = await service.listParticipants(room.name);
          // Read once for the room, and both questions answered from it.
          const rights = await readCallRights(
            supabase,
            room.name,
            connections.map((p) => p.identity.split("~")[0]),
          );
          const outside = await connectionsOutside(supabase, room.name, connections, rights);
          const results = await Promise.allSettled(
            outside.map((p) => service.removeParticipant(room.name, p.identity)),
          );
          removed += results.filter((r) => r.status === "fulfilled").length;
          const gone = new Set(outside.map((p) => p.identity));
          updated += await reconcileConnections(
            supabase,
            service,
            room.name,
            connections.filter((p) => !gone.has(p.identity)),
            rights,
          );
        } catch (err) {
          console.error("[refresh_calls] room", room.name, err);
          unreachable = true;
        }
      }));
    }));

    return CustomResponse.success({
      connections_removed: removed,
      connections_updated: updated,
      livekit_error: unreachable ? "livekit_unreachable" : null,
    });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});
