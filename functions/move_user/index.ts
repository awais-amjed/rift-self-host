import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { DataPacket_Kind, ParticipantInfo } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomService } from "../_shared/livekit.ts";

/**
 * Pull a member from the voice channel they're in into another one.
 *
 * Staff-only (server admin or channel manager), and it can only reach someone
 * who is already in a call: there is no way to make a client join from nothing.
 *
 * This is a **signal, not a server-side move**. LiveKit can relocate a
 * participant between rooms itself, but Rift's channels are end-to-end
 * encrypted and the client is what holds the keys — a connection dragged
 * sideways underneath it would be sitting in a room whose key it never fetched,
 * with the sidebar, presence and chat all still pointing at the old channel. So
 * the target is *told* to join, over a data packet, and takes the ordinary join
 * path: fetch a token, fetch the channel key, connect, publish. Everything that
 * makes a normal join correct stays in one place.
 *
 * The packet is sent through the LiveKit API, which means it arrives with no
 * sender — a peer cannot forge that, so "came from the server" is the client's
 * authenticity check (see `VoiceSignal` on the Flutter side).
 *
 * Every device they're joined from is moved, the same rule moderation uses.
 * Their screen share is not: switching channels stops it client-side, which is
 * the honest outcome — a share belongs to the call it was started in.
 */

/** Topic and payload version. Keep in sync with `lib/logic/services/voice_signal.dart`. */
const MOVE_TOPIC = "rift.move";
const SIGNAL_VERSION = 1;

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { target_user_id, channel_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!target_user_id || !channel_id) {
      return CustomResponse.error(
        "Missing required fields: target_user_id, channel_id",
        EC.MISSING_FIELDS,
      );
    }

    // Moving people is moderation, so it follows the moderation permission:
    // channel managers and admins. There is no RPC to defer to — nothing is
    // written down — so the check is here.
    if (!auth.isServerAdmin && !auth.isChannelManager) {
      return CustomResponse.error("Not allowed to move members", EC.PERMISSION_DENIED);
    }

    // The destination has to be a voice channel *on this server*: the caller
    // supplies it, and a room name is just a channel id, so without the
    // server_id filter this would be a way to push someone into another
    // server's call.
    const { data: channelData, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}, ${DBSchema.channels.channelType}`)
      .eq(DBSchema.channels.id, channel_id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .single();

    if (channelError || !channelData) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, channelError);
    }
    if ((channelData as Record<string, any>)[DBSchema.channels.channelType] !== "voice") {
      return CustomResponse.error(
        "Members can only be moved into a voice channel",
        EC.CHANNEL_TYPE_INVALID,
      );
    }

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

    // Only rooms that exist come back, so this is one call rather than one
    // listParticipants per channel on a server where nobody is in voice.
    const rooms = await roomService.listRooms(channelIds);

    let foundAnywhere = false;
    let moved = 0;
    const payload = new TextEncoder().encode(
      JSON.stringify({
        v: SIGNAL_VERSION,
        type: "move",
        channel_id,
        moved_by: auth.userId,
      }),
    );

    for (const room of rooms) {
      const participants = await roomService.listParticipants(room.name);
      const identities = voiceConnectionsOf(participants, target_user_id);
      if (identities.length === 0) continue;

      foundAnywhere = true;
      // Already where they're being sent — nothing to say to them.
      if (room.name === channel_id) continue;

      await roomService.sendData(room.name, payload, DataPacket_Kind.RELIABLE, {
        destinationIdentities: identities,
        topic: MOVE_TOPIC,
      });
      moved += identities.length;
    }

    if (!foundAnywhere) {
      return CustomResponse.error(
        "That member isn't in a voice channel",
        EC.USER_NOT_IN_VOICE,
      );
    }

    return CustomResponse.success({ channel_id, connections_moved: moved });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * The target's own connections in a room — one per device — with screen shares
 * left out, since telling a share to join a channel means nothing.
 *
 * Identities are "<userId>~<device>", plus a "_screenshare" suffix for that
 * device's share, so the user id is what to match on.
 */
function voiceConnectionsOf(participants: ParticipantInfo[], userId: string): string[] {
  return participants
    .filter((p) => p.identity.split("~")[0] === userId && !p.identity.endsWith("_screenshare"))
    .map((p) => p.identity);
}
