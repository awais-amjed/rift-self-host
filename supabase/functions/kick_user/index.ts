import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { ParticipantInfo } from "livekit-server-sdk";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { roomParticipantsAcross, roomServicesFrom } from "../_shared/livekit.ts";

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
      return CustomResponse.error("Not allowed to disconnect members", EC.PERMISSION_DENIED);
    case "self":
      return CustomResponse.error("You cannot disconnect yourself", EC.PERMISSION_DENIED);
    case "target_not_found":
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND);
    case "target_admin":
      return CustomResponse.error("Admins cannot be disconnected", EC.PERMISSION_DENIED);
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
    const { target_user_id } = await req.json();
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    const userId = await verifyJwt(token);
    if (!userId) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    if (typeof target_user_id !== "string" || target_user_id.length === 0) {
      return CustomResponse.error("Missing required field: target_user_id", EC.MISSING_FIELDS);
    }
    if (!UUID.test(target_user_id)) {
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND);
    }

    // Nothing is written down, so there is no RPC that does the act; the one
    // asked here answers the checks, which match `moderate_user`'s
    // deliberately — the same people may do it, and to the same people — and
    // where to look. One call where there were eight or more.
    const { data: facts, error: factsError } = await supabase.rpc("voice_moderation_facts", {
      p_caller: userId,
      p_target: target_user_id,
    });
    if (factsError || !facts) {
      return CustomResponse.error("Unexpected error", EC.DB_ERROR, factsError);
    }
    const refused = refusal((facts as Record<string, any>).reason);
    if (refused) return refused;

    // A server may hold calls on more than one LiveKit, and a member kicked
    // out of one must not be left sitting in another. Each node is asked; the
    // ones not holding a given room answer empty.
    const services = roomServicesFrom((facts as Record<string, any>).nodes);
    if (services.length === 0) return refusal("credentials_missing")!;

    // Only from a call the caller manages, the only rooms asked about. A call
    // they do not manage answers as if the target were not in voice at all,
    // since a private one is not theirs to know about.
    const channelIds = ((facts as Record<string, any>).rooms ?? []) as string[];
    if (channelIds.length === 0) {
      return CustomResponse.error("That member isn't in a voice channel", EC.USER_NOT_IN_VOICE);
    }

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

    // Find them everywhere first, then remove everywhere: a member can be in
    // two calls from two devices, and both go — now possibly on two nodes.
    // The service comes back with each roster so the removal is sent to the
    // node that actually has them.
    const rosters = await roomParticipantsAcross(services, rooms);
    const toRemove = rosters.flatMap(({ room, participants, service }) =>
      connectionsOf(participants, target_user_id).map((identity) => ({ room, identity, service }))
    );
    // Each on its own: one connection that has already gone must not stop
    // the rest being removed.
    const results = await Promise.allSettled(
      toRemove.map(({ room, identity, service }) => service.removeParticipant(room, identity)),
    );
    for (const r of results) {
      if (r.status === "rejected") console.error("[kick_user] remove", r.reason);
    }
    const removed = toRemove.length;

    if (removed === 0) {
      return CustomResponse.error("That member isn't in a voice channel", EC.USER_NOT_IN_VOICE);
    }

    return CustomResponse.success({ connections_removed: removed });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
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
