import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import {
  LiveKitNode,
  livekitCredentials,
  nodeKeyPair,
  normaliseHost,
} from "../_shared/livekit.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * A LiveKit token for a call between two members (`dm_calls`, 001).
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
    const { call_id, screen_share, sound_share, device_id, preferred_node_id } =
      await req.json();

    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;

    if (typeof call_id !== "string" || call_id.length === 0) {
      return CustomResponse.error("Missing required field: call_id", EC.MISSING_FIELDS);
    }

    const wantsShare = screen_share === true || sound_share === true;
    const [
      { data: claim, error: claimError },
      { data: mayConnect },
      { data: mayShare },
      { data: userData, error: userError },
      credentials,
      { data: limitsRow },
    ] = await Promise.all([
      supabase.rpc("claim_dm_call_room", {
        p_call: call_id,
        p_user: auth.userId,
        p_preferred: typeof preferred_node_id === "string" ? preferred_node_id : null,
      }),
      supabase.rpc("user_has_permission", { p_user: auth.userId, p_name: "CONNECT" }),
      wantsShare
        ? supabase.rpc("user_has_permission", { p_user: auth.userId, p_name: "SCREEN_SHARE" })
        : Promise.resolve({ data: null }),
      supabase
        .from(DBSchema.users.tableName)
        .select(DBSchema.users.displayName)
        .eq(DBSchema.users.id, auth.userId)
        .single(),
      livekitCredentials(supabase, auth.serverId),
      supabase
        .from(DBSchema.servers.tableName)
        .select(DBSchema.servers.maxShareMbps)
        .eq(DBSchema.servers.id, auth.serverId)
        .single(),
    ]);

    if (claimError) {
      return CustomResponse.error("Error reading the call", EC.DB_ERROR, claimError);
    }
    // One answer for "no such call", "not yours" and "over": a call id you are
    // not on should not confirm that it exists.
    if ((claim as Record<string, any> | null)?.allowed !== true) {
      return CustomResponse.error("This call has ended", EC.CALL_NOT_FOUND);
    }
    if (mayConnect !== true) {
      return CustomResponse.error("You cannot join calls on this server", EC.PERMISSION_DENIED);
    }
    if (wantsShare && mayShare !== true) {
      return CustomResponse.error("You cannot share here", EC.PERMISSION_DENIED);
    }
    if (userError || !userData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, userError);
    }
    if (!credentials) {
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }

    const room = `dm-${call_id}`;

    // Where the call is: the node the claim named, or the server's own
    // LiveKit on a server that has no node rows.
    let node = nodeOf((claim as Record<string, any>).node);
    let pair = await nodeKeyPair(supabase, node, credentials);
    let host = node ? normaliseHost(node.url) : credentials.host;
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
        p_user: auth.userId,
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
        EC.UNEXPECTED_ERROR,
      );
    }

    // Identity as for a channel — "<userId>~<device>" plus a share suffix —
    // because the client's roster, keys and tiles all parse it that way.
    const deviceSuffix =
      (typeof device_id === "string" ? device_id : "").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16) ||
      "default";
    let identity = `${auth.userId}~${deviceSuffix}`;
    if (screen_share === true) {
      identity = `${identity}_screenshare`;
    } else if (sound_share === true) {
      identity = `${identity}_soundshare`;
    }

    const at = new AccessToken(pair!.apiKey, pair!.apiSecret, {
      identity,
      name: (userData as Record<string, any>)[DBSchema.users.displayName],
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
      canUpdateOwnMetadata: true,
      roomAdmin: false,
    });

    const limits = (limitsRow ?? {}) as Record<string, any>;
    return CustomResponse.success({
      token: await at.toJwt(),
      identity,
      room,
      livekit_url: node?.url ?? credentials.url,
      max_share_mbps: Number(limits[DBSchema.servers.maxShareMbps] ?? 0),
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
