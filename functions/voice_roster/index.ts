import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomService, voiceUserId } from "../_shared/livekit.ts";

/**
 * Who is in which voice channel on this server, right now: `{userId: channelId}`.
 *
 * Members learn about each other's channel *changes* from broadcasts on
 * `voice:<serverId>`, which is stateless — a client that just opened the app
 * has missed every one of them. This is the snapshot it starts from, and it
 * comes from LiveKit rather than from asking the room, because LiveKit is the
 * only thing that actually knows: a client can lie about where it is, and one
 * that crashed never got to say it left.
 *
 * Readable by any member — being in a call is not a secret from the people who
 * can see the channel list.
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
    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;

    const roomService = await livekitRoomService(supabase, auth.serverId);
    if (!roomService) {
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }

    const { data: channels } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, auth.serverId);

    const channelIds = (channels ?? []).map(
      (c) => (c as Record<string, any>)[DBSchema.channels.id] as string,
    );

    // Rooms are named by channel id, and only rooms that exist come back — so
    // an idle server costs one call, not one per channel.
    const rooms = await roomService.listRooms(channelIds);

    const roster: Record<string, string> = {};
    for (const room of rooms) {
      const participants = await roomService.listParticipants(room.name);
      for (const participant of participants) {
        const userId = voiceUserId(participant.identity);
        // Someone joined from two devices in different channels lands here
        // twice; the last room wins, and their own client is the only one that
        // could say which is "theirs". Rare enough to leave alone.
        if (userId) roster[userId] = room.name;
      }
    }

    return CustomResponse.success({ roster });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
