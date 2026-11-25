import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { DataPacket_Kind, RoomServiceClient } from "livekit-server-sdk";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import {
  livekitCredentials,
  livekitRoomServiceForChannel,
  nodeKeyPair,
  normaliseHost,
} from "../_shared/livekit.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** The app's `ClipSignal.topic`. */
const CLIP_TOPIC = "rift.clip";
const SIGNAL_VERSION = 2;

/** The longest clip a client keeps (`ClipSignal.maxSeconds`). */
const MAX_SECONDS = 120;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Tell a call that one of its members just kept its last stretch.
 *
 * The clip itself never leaves the clipper's device. What the others get is a
 * notice, and it comes from here rather than from the clipper: a packet sent
 * through LiveKit's API has no sender, which no member can fake, so the app
 * believes only those. A member's own packet needed `canPublishData`, which is
 * the soundboard right, so a member without it clipped unannounced
 * (migration 037 says the rest).
 *
 * Takes `channel_id` for a voice channel's call or `call_id` for a DM call,
 * the device the clip was made on (`device_id`, as the token functions take
 * it) and `seconds`. The packet names that device's voice identity, and is
 * sent only while that connection is in the room — so a notice is about
 * somebody the call can see. At most one a minute per member
 * (`note_clip_allowed`); past it, the answer is `noted: false` and nothing is
 * sent, which is not an error.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, call_id, device_id, seconds } = await req.json();

    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;

    const isChannel = typeof channel_id === "string" && channel_id.length > 0;
    const isDm = typeof call_id === "string" && call_id.length > 0;
    if (isChannel === isDm) {
      return CustomResponse.error("Name the call: channel_id or call_id", EC.MISSING_FIELDS);
    }
    if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
      return CustomResponse.error("Missing required field: seconds", EC.MISSING_FIELDS);
    }
    const id = isChannel ? channel_id : call_id;
    if (!UUID.test(id)) {
      return CustomResponse.error("You are not in that call", EC.USER_NOT_IN_VOICE);
    }

    // The same rule the token functions mint by, so this is the identity
    // that device joined with.
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    const identity = `${auth.userId}~${deviceSuffix}`;

    const room = isChannel ? id : `dm-${id}`;
    const service = isChannel
      ? await livekitRoomServiceForChannel(supabase, auth.serverId, id)
      : await dmCallService(id, auth.userId, auth.serverId);
    if (!service) {
      return CustomResponse.error("You are not in that call", EC.USER_NOT_IN_VOICE);
    }

    // In the room now, on that connection. A room that does not answer is a
    // refusal: being there is the whole reason the notice is believed.
    let present: string[];
    try {
      present = (await service.listParticipants(room)).map((p: { identity: string }) => p.identity);
    } catch {
      return CustomResponse.error(
        "The voice server is not answering",
        EC.VOICE_SERVER_UNREACHABLE,
      );
    }
    if (!present.includes(identity)) {
      return CustomResponse.error("You are not in that call", EC.USER_NOT_IN_VOICE);
    }

    const { data: allowed, error: limitError } = await supabase.rpc("note_clip_allowed", {
      p_user: auth.userId,
    });
    if (limitError) {
      return CustomResponse.error("Error reading the notice limit", EC.DB_ERROR, limitError);
    }
    if (allowed !== true) {
      return CustomResponse.success({ noted: false });
    }

    const payload = new TextEncoder().encode(
      JSON.stringify({
        v: SIGNAL_VERSION,
        type: "clipped",
        identity,
        seconds: Math.min(Math.max(Math.round(seconds), 1), MAX_SECONDS),
      }),
    );
    // Everybody else in the room. The clipper's own connections already know.
    const others = present.filter((p) => p.split("~")[0] !== auth.userId);
    if (others.length > 0) {
      await service.sendData(room, payload, DataPacket_Kind.RELIABLE, {
        destinationIdentities: others,
        topic: CLIP_TOPIC,
      });
    }
    return CustomResponse.success({ noted: true });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * The admin API for the node holding DM call [callId], when [userId] is on it.
 *
 * `claim_dm_call_room` is what the token function asks, and answers the node
 * the call was put on; a call the caller is not on, or that is over, is not
 * allowed and comes back null — as "not in that call", the same as for a
 * channel.
 */
async function dmCallService(
  callId: string,
  userId: string,
  serverId: string,
): Promise<RoomServiceClient | null> {
  const [{ data: claim, error }, credentials] = await Promise.all([
    supabase.rpc("claim_dm_call_room", { p_call: callId, p_user: userId }),
    livekitCredentials(supabase, serverId),
  ]);
  const answer = claim as Record<string, any> | null;
  if (error || answer?.allowed !== true || !credentials) return null;
  const raw = answer.node as Record<string, any> | null | undefined;
  const node = raw?.id && raw?.url
    ? { id: raw.id as string, url: raw.url as string, label: "", isDefault: raw.is_default === true }
    : null;
  const pair = await nodeKeyPair(supabase, node, credentials);
  if (!pair) return null;
  return new RoomServiceClient(
    node ? normaliseHost(node.url) : credentials.host,
    pair.apiKey,
    pair.apiSecret,
  );
}
