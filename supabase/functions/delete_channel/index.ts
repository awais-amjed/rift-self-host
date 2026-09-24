import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServiceForChannel } from "../_shared/livekit.ts";

/**
 * Delete a channel, and the call going on inside it.
 *
 * The row delete is a plain table call gated by `channels_delete_managers`, and
 * is done with the caller's own JWT so that policy is what decides. What a
 * table call cannot do is empty the LiveKit room: rooms are named by channel
 * id, so deleting the row would leave everyone talking happily in a room
 * belonging to a channel that no longer exists, until they each noticed.
 *
 * So the room is deleted here, with the API secret — which is the same reason
 * `get_channel_token` and `moderate_user` are edge functions. Deleting a room
 * disconnects every participant in it, which *is* the kick.
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
    const { channel_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!channel_id) {
      return CustomResponse.error("Missing required field: channel_id", EC.MISSING_FIELDS);
    }

    // The room goes first. If the delete below is refused the room comes back
    // the moment someone rejoins (get_channel_token recreates it), whereas the
    // other order can leave a live room with no channel behind it.
    const roomError = await deleteRoom(auth.serverId, channel_id);

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { data, error } = await asCaller
      .from(DBSchema.channels.tableName)
      .delete()
      .eq(DBSchema.channels.id, channel_id)
      .select(DBSchema.channels.id);

    if (error) {
      return CustomResponse.error("Error deleting channel", EC.DB_ERROR, error);
    }
    // RLS turns "not allowed" into "nothing matched", so an empty result is the
    // refusal — not a channel that was already gone, which is equally fine to
    // report as not found.
    if (!data || data.length === 0) {
      return CustomResponse.error(
        "Channel not found, or not yours to delete",
        EC.PERMISSION_DENIED,
      );
    }

    return CustomResponse.success({ channel_id, livekit_error: roomError });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Drops the LiveKit room for [channelId], disconnecting everyone in it.
 *
 * Never throws: a channel with no call in it has no room, and a LiveKit that
 * can't be reached must not stop an admin deleting a channel. The failure is
 * reported back rather than swallowed.
 */
async function deleteRoom(serverId: string, channelId: string): Promise<string | null> {
  try {
    const roomService = await livekitRoomServiceForChannel(supabase, serverId, channelId);
    if (!roomService) return "credentials_missing";

    await roomService.deleteRoom(channelId);
    return null;
  } catch (err) {
    // Includes "room does not exist", which is the normal case for a text
    // channel or an empty voice one.
    return String(err);
  }
}
