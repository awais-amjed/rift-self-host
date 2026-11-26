import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { DataPacket_Kind, ParticipantInfo } from "livekit-server-sdk";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { roomParticipantsAcross, roomServicesFrom, voiceUserId } from "../_shared/livekit.ts";

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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The answer for a refusal `voice_moderation_facts` gave, in the words and
 * codes this function always answered with, or null for `ok`.
 */
function refusal(reason: string): Response | null {
  switch (reason) {
    case "ok":
      return null;
    case "user_not_found":
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
    case "user_banned":
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    case "not_allowed":
      return CustomResponse.error("Not allowed to move members", EC.PERMISSION_DENIED);
    case "target_not_found":
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND);
    case "target_admin":
      return CustomResponse.error("Admins cannot be moved", EC.PERMISSION_DENIED);
    case "channel_not_found":
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    case "not_voice":
      return CustomResponse.error(
        "Members can only be moved into a voice channel",
        EC.CHANNEL_TYPE_INVALID,
      );
    case "credentials_missing":
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    default:
      return CustomResponse.error("Unexpected error", EC.DB_ERROR);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { target_user_id, channel_id } = await req.json();
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    const userId = await verifyJwt(token);
    if (!userId) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    if (!target_user_id || !channel_id) {
      return CustomResponse.error(
        "Missing required fields: target_user_id, channel_id",
        EC.MISSING_FIELDS,
      );
    }
    if (typeof target_user_id !== "string" || !UUID.test(target_user_id)) {
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND);
    }
    if (typeof channel_id !== "string" || !UUID.test(channel_id)) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    }

    // Moving people is moderation, so it follows the moderation permission:
    // channel managers and admins, never onto an administrator (as for a
    // kick), only somebody of this server, and only into a voice channel of
    // this server the caller manages — a room name is just a channel id, so
    // without that this would push someone into another server's call. There
    // is no RPC that does the act — nothing is written down — so the one
    // asked here answers the checks and where to look, in one call where
    // there were eight or more.
    const { data: facts, error: factsError } = await supabase.rpc("voice_moderation_facts", {
      p_caller: userId,
      p_target: target_user_id,
      p_destination: channel_id,
    });
    if (factsError || !facts) {
      return CustomResponse.error("Unexpected error", EC.DB_ERROR, factsError);
    }
    const refused = refusal((facts as Record<string, any>).reason);
    if (refused) return refused;

    // Only to find them: the move itself is a packet telling their client to
    // rejoin elsewhere, and its next `get_channel_token` resolves the node
    // for the destination. So a move between two channels on two different
    // LiveKits needs nothing extra here — the client reconnects, which is
    // what it was already doing.
    const services = roomServicesFrom((facts as Record<string, any>).nodes);
    if (services.length === 0) return refusal("credentials_missing")!;

    // Out of a call the caller manages, the only rooms asked about: a
    // private call they are not in is not theirs to empty, or to learn the
    // target is in.
    const channelIds = ((facts as Record<string, any>).rooms ?? []) as string[];

    // Only rooms that exist come back, so this is one call per node rather
    // than one listParticipants per channel on a server where nobody is in
    // voice.
    const rooms = (await Promise.all(
      services.map(async ({ service }) => {
        try {
          return await service.listRooms(channelIds);
        } catch {
          return [];
        }
      }),
    )).flat();

    let foundAnywhere = false;
    let moved = 0;
    const payload = new TextEncoder().encode(
      JSON.stringify({
        v: SIGNAL_VERSION,
        type: "move",
        channel_id,
        moved_by: userId,
      }),
    );

    const found = (await roomParticipantsAcross(services, rooms))
      .map(({ room, participants, service }) => ({
        room,
        service,
        identities: voiceConnectionsOf(participants, target_user_id),
      }))
      .filter(({ identities }) => identities.length > 0);

    foundAnywhere = found.length > 0;
    // Already where they're being sent — nothing to say to them.
    const toMove = found.filter(({ room }) => room !== channel_id);
    const results = await Promise.allSettled(
      toMove.map(({ room, identities, service }) =>
        service.sendData(room, payload, DataPacket_Kind.RELIABLE, {
          destinationIdentities: identities,
          topic: MOVE_TOPIC,
        })
      ),
    );
    for (const r of results) {
      if (r.status === "rejected") console.error("[move_user] send", r.reason);
    }
    moved = toMove.reduce((n, { identities }) => n + identities.length, 0);

    if (!foundAnywhere) {
      return CustomResponse.error(
        "That member isn't in a voice channel",
        EC.USER_NOT_IN_VOICE,
      );
    }

    return CustomResponse.success({ channel_id, connections_moved: moved });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});

/** The target's own connections in a room — one per device, shares excluded. */
function voiceConnectionsOf(participants: ParticipantInfo[], userId: string): string[] {
  return participants
    .filter((p) => voiceUserId(p.identity) === userId)
    .map((p) => p.identity);
}
