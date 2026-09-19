import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { ParticipantInfo } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomService, roomParticipants } from "../_shared/livekit.ts";

/**
 * Disconnect a member from the voice channel they are in.
 *
 * The transient half of moderation, and deliberately the *weakest* tool here:
 * nothing is written down, and the target may walk straight back in. It is for
 * ending a situation now — someone left a hot mic in an empty room, someone is
 * shouting — where a ban would be the wrong answer and a mute does not go far
 * enough. Ban is the one that persists; see `moderate_user`.
 *
 * Staff-only (server admin or channel manager), the same authority `move_user`
 * takes, because it is the same kind of power over a call.
 *
 * Unlike a move, this ends **every** connection the target holds here,
 * screen share included. A move leaves the share to stop client-side because
 * the person is still in the call and their client can tidy up; a kick means
 * they are gone, and leaving a published screen behind after its owner has
 * been removed is a stream nobody can stop.
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
    const { target_user_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!target_user_id) {
      return CustomResponse.error("Missing required field: target_user_id", EC.MISSING_FIELDS);
    }

    // Nothing is written down, so there is no RPC to defer the rules to and
    // the checks live here. They match `moderate_user`'s deliberately: the
    // same people may do it, and to the same people.
    if (!auth.isServerAdmin && !auth.isChannelManager) {
      return CustomResponse.error("Not allowed to disconnect members", EC.PERMISSION_DENIED);
    }
    if (target_user_id === auth.userId) {
      return CustomResponse.error("You cannot disconnect yourself", EC.PERMISSION_DENIED);
    }

    // Scoped to this server: without it, a member id from anywhere would let a
    // staff member reach into a call they have no standing in.
    const { data: targetData, error: targetError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.isServerAdmin}`)
      .eq(DBSchema.users.id, target_user_id)
      .eq(DBSchema.users.serverId, auth.serverId)
      .single();

    if (targetError || !targetData) {
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND, targetError);
    }
    if ((targetData as Record<string, any>)[DBSchema.users.isServerAdmin] === true) {
      return CustomResponse.error("Admins cannot be disconnected", EC.PERMISSION_DENIED);
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
    if (channelIds.length === 0) {
      return CustomResponse.error("That member isn't in a voice channel", EC.USER_NOT_IN_VOICE);
    }

    // Only rooms that exist come back, so this is one call rather than one
    // listParticipants per channel on a server where nobody is in voice.
    const rooms = await roomService.listRooms(channelIds);

    // Find them everywhere first, then remove everywhere: a member can be in
    // two calls from two devices, and both go.
    const rosters = await roomParticipants(roomService, rooms);
    const toRemove = rosters.flatMap(({ room, participants }) =>
      connectionsOf(participants, target_user_id).map((identity) => ({ room, identity }))
    );
    await Promise.all(
      toRemove.map(({ room, identity }) => roomService.removeParticipant(room, identity)),
    );
    const removed = toRemove.length;

    if (removed === 0) {
      return CustomResponse.error("That member isn't in a voice channel", EC.USER_NOT_IN_VOICE);
    }

    return CustomResponse.success({ connections_removed: removed });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Every connection the target holds in a room — each device *and* its screen
 * share.
 *
 * Matches the raw `<userId>~<device>` prefix rather than going through
 * `voiceUserId`, which drops shares on purpose because it is used for counting
 * people. Here a share is exactly what must not be left behind.
 */
function connectionsOf(participants: ParticipantInfo[], userId: string): string[] {
  return participants
    .filter((p) => p.identity.split("~")[0] === userId)
    .map((p) => p.identity);
}
