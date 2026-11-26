import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { publishSources } from "../_shared/moderation.ts";
import { admitWatcher, WATCH_TOKEN_TTL, watchGrant, watchIdentity } from "../_shared/watch.ts";
import {
  KeyPair,
  LiveKitCredentials,
  LiveKitNode,
  nodeKeyPair,
  normaliseHost,
  preferredNode,
} from "../_shared/livekit.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * A LiveKit token for a call between two members (`dm_calls`).
 *
 * The same shape of answer as `get_channel_token` — token, identity, the node
 * to connect to, the share bitrate — for a room named after the call rather
 * than a channel: `dm-<callId>`. The prefix keeps it out of everything that
 * reads rooms as channels (`voice_roster`, `moderate_user`), which is where a
 * private call must not show up.
 *
 * **What this does not check is who may call whom.** That was decided when the
 * row was written (`start_dm_call`), and `claim_dm_call_room` only asks whether
 * this member is on the call and whether it is theirs to join yet: the caller
 * from the first ring, so their line is open when the callee picks up, the
 * callee once they have answered, and nobody after it has ended.
 *
 * **Nor does it carry a moderator's voice mute.** `is_muted` and `is_deafened`
 * are about the server's voice channels, which a moderator is there to keep in
 * order. A call between two people who both chose it is not that room.
 */
async function openRoom(service: RoomServiceClient, room: string): Promise<boolean> {
  try {
    // Two people. A second device of either one is let in by LiveKit, but the
    // room does not grow past what a call between two could want.
    await service.createRoom({ name: room, maxParticipants: 8, emptyTimeout: 60 });
    return true;
  } catch {
    return false;
  }
}

/**
 * The answer for a refusal `dm_call_join_facts` gave, in the words and codes
 * this function always answered with, or null for `ok`.
 */
function refusal(reason: string): Response | null {
  switch (reason) {
    case "ok":
      return null;
    case "user_not_found":
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
    case "user_banned":
      return CustomResponse.error("User is banned", EC.USER_BANNED);
    case "call_not_found":
      return CustomResponse.error("This call has ended", EC.CALL_NOT_FOUND);
    case "no_connect":
      return CustomResponse.error("You cannot join calls on this server", EC.PERMISSION_DENIED);
    case "no_share":
      return CustomResponse.error("You cannot share here", EC.PERMISSION_DENIED);
    case "credentials_missing":
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    default:
      return CustomResponse.error("Error reading the call", EC.DB_ERROR);
  }
}

function nodeOf(raw: Record<string, any> | null | undefined): LiveKitNode | null {
  if (!raw?.id || !raw?.url) return null;
  return {
    id: raw.id,
    url: raw.url,
    label: raw.label ?? "",
    isDefault: raw.is_default === true,
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { call_id, screen_share, sound_share, watch, device_id, preferred_node_id } =
      await req.json();

    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    // The JWT is checked here, against the stack's keys; who the caller is on
    // this server (a member, banned, a server being deleted) is the
    // database's first answer below.
    const userId = await verifyJwt(token);
    if (!userId) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    if (typeof call_id !== "string" || call_id.length === 0) {
      return CustomResponse.error("Missing required field: call_id", EC.MISSING_FIELDS);
    }
    // Anything that is not a call id is no call, and says so in the same
    // words as one that is not yours — not a database error about the cast.
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(call_id)) {
      return CustomResponse.error("This call has ended", EC.CALL_NOT_FOUND);
    }

    const wantsShare = screen_share === true || sound_share === true;
    // A watch connection only receives (`_shared/watch.ts`), as for a channel.
    const wantsWatch = watch === true;
    if (wantsWatch && wantsShare) {
      return CustomResponse.error("A connection either shares or watches", EC.PERMISSION_DENIED);
    }
    // ── Everything it decides from, in one call ──
    //
    // `dm_call_join_facts` (082) answers what this function used to ask in
    // nine round trips, in the order it weighed them: membership, the call
    // (one answer for "no such call", "not yours" and "over": a call id you
    // are not on should not confirm that it exists), CONNECT, SCREEN_SHARE for
    // a share, then the server's LiveKit. The claim is the one write, and a
    // watch makes none. The keys come back with it: this function is what
    // signs.
    const kind = wantsWatch ? "watch" : wantsShare ? "share" : "voice";
    const { data: factsData, error: factsError } = await supabase.rpc("dm_call_join_facts", {
      p_call: call_id,
      p_user: userId,
      p_kind: kind,
      p_preferred: preferredNode(preferred_node_id),
    });
    if (factsError) {
      return CustomResponse.error("Error reading the call", EC.DB_ERROR, factsError);
    }
    const facts = (factsData ?? {}) as Record<string, any>;
    const refused = refusal(String(facts.reason ?? ""));
    if (refused) return refused;

    const displayName = facts.display_name as string;
    // Asked for every connection: the call's own shares too, from a phone
    // or a browser, and its token names the screen only with this.
    const mayShare = facts.screen_share === true;
    // The soundboard right, as a channel's (`_shared/call_rights.ts`): a
    // clip is sound in the call, so it takes Speak as well. A DM call has
    // no channel to override them, so these are the server's bits — the
    // ones the app's own button asks.
    const maySpeak = facts.speak === true;
    const maySoundboard = facts.soundboard === true;
    const maxShareMbps = Number(facts.max_share_mbps ?? 0);
    const credentialsRow = facts.credentials as Record<string, string>;
    const credentials: LiveKitCredentials = {
      host: normaliseHost(credentialsRow.url),
      apiKey: credentialsRow.api_key,
      apiSecret: credentialsRow.api_secret,
      url: credentialsRow.url,
    };

    const room = `dm-${call_id}`;

    // Identity as for a channel — "<userId>~<device>" plus a share or watch
    // suffix — because the client's roster, keys and tiles all parse it that
    // way.
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    const voiceIdentity = `${userId}~${deviceSuffix}`;

    // Where the call is: the node the claim named, or the server's own
    // LiveKit on a server that has no node rows.
    // The key belongs to the node, and came with it: null keys are a region
    // with none, treated below as a region that did not answer.
    const claimed = facts.node as Record<string, any> | null;
    let node = nodeOf(claimed);
    let pair: KeyPair | null = !claimed
      ? credentials
      : claimed.api_key && claimed.api_secret
      ? { apiKey: claimed.api_key, apiSecret: claimed.api_secret }
      : null;
    let host = node ? normaliseHost(node.url) : credentials.host;

    // A watch connection joins the call this device is already in: no room is
    // opened and the call is never moved, and the voice connection being in
    // the room is the condition for the token at all.
    if (wantsWatch) {
      const service = pair ? new RoomServiceClient(host, pair.apiKey, pair.apiSecret) : null;
      if (!pair || !service || !(await admitWatcher(service, room, voiceIdentity))) {
        return CustomResponse.error("Join the call before watching in it", EC.USER_NOT_IN_VOICE);
      }
      const watchToken = new AccessToken(pair.apiKey, pair.apiSecret, {
        identity: watchIdentity(voiceIdentity),
        name: displayName,
        ttl: WATCH_TOKEN_TTL,
      });
      watchToken.addGrant(watchGrant(room, true));
      return CustomResponse.success({
        token: await watchToken.toJwt(),
        identity: watchIdentity(voiceIdentity),
        room,
        livekit_url: node?.url ?? credentials.url,
        max_share_mbps: maxShareMbps,
      });
    }
    let opened = pair
      ? await openRoom(new RoomServiceClient(host, pair.apiKey, pair.apiSecret), room)
      : false;

    // A region that does not answer sends the call home, once — the same
    // fallback a pinned channel gets, for the same reason: two people who want
    // to talk should not be stranded because one box is down. Only while the
    // call has nobody in it yet would this move anyone, and that is the only
    // time it can be asked: the caller is first in.
    if (!opened && node && !node.isDefault) {
      const { data: moved } = await supabase.rpc("claim_dm_call_room", {
        p_call: call_id,
        p_user: userId,
        p_move_to_default: true,
      });
      const fallback = nodeOf((moved as Record<string, any> | null)?.node);
      if (fallback && fallback.id !== node.id) {
        node = fallback;
        pair = await nodeKeyPair(supabase, fallback, credentials);
        host = normaliseHost(fallback.url);
        opened = pair
          ? await openRoom(new RoomServiceClient(host, pair.apiKey, pair.apiSecret), room)
          : false;
      }
    }

    if (!opened) {
      return CustomResponse.error(
        node ? `${node.label} is not answering, so this call could not be opened`
             : "Failed to ensure LiveKit room exists",
        EC.VOICE_SERVER_UNREACHABLE,
      );
    }

    let identity = voiceIdentity;
    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    } else if (sound_share === true) {
      identity = `${identity}_soundshare`;
    }

    const at = new AccessToken(pair!.apiKey, pair!.apiSecret, {
      identity,
      name: displayName,
      ttl: "1h",
    });
    at.addGrant({
      roomCreate: false,
      roomJoin: true,
      room,
      canPublish: true,
      // A share connection only publishes, as in a channel: one that could
      // subscribe would be a second pair of ears nobody sees in the call.
      canSubscribe: !wantsShare,
      // The microphone always: a DM call was never minted with the server's
      // flags or `SPEAK` (`moderate_user`). The screen only with
      // `SCREEN_SHARE`, as in a channel (`publishSources`).
      canPublishSources: publishSources(false, false, mayShare === true),
      // Nor does it send packets (`_shared/moderation.ts`). The call's own
      // connection sends one only to press a soundboard clip, so it may only
      // with that right; the clip notice comes from the server (`note_clip`).
      // Read once, at minting: a role change mid-call takes effect at the next
      // join, as a channel's does.
      canPublishData: !wantsShare && maySpeak === true && maySoundboard === true,
      canUpdateOwnMetadata: true,
      roomAdmin: false,
    });

    return CustomResponse.success({
      token: await at.toJwt(),
      identity,
      room,
      livekit_url: node?.url ?? credentials.url,
      max_share_mbps: maxShareMbps,
    });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});
