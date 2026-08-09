import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { RoomServiceClient, TrackSource } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livePermissions, moderationMetadata } from "../_shared/moderation.ts";

/**
 * Server-side mute / deafen / ban.
 *
 * The authorisation and the row write stay in the `moderate_user` RPC — this
 * calls it as the caller, so the "admins only, not yourself, not another
 * admin" rules live in one place. What the RPC cannot do is reach LiveKit:
 * moderation used to be enforced *only* in the grant minted by
 * `get_channel_token`, which meant flipping the flag did nothing to anyone
 * already in the call, and nothing on rejoin either while the client's cached
 * token was still inside its hour. A moderator watched a muted member keep
 * talking.
 *
 * So this is an edge function for the usual reason: it holds the LiveKit API
 * secret. After the RPC lands it pushes the new permissions and metadata onto
 * every live connection the target has — every device, plus their screenshare
 * — and force-mutes a published microphone so the audio stops now rather than
 * at their next publish.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** Maps the RPC's RAISE EXCEPTION messages onto our machine codes. */
function rpcErrorResponse(message: string): Response {
  if (message.includes("not_authorized")) {
    return CustomResponse.error("Not allowed to moderate members", EC.PERMISSION_DENIED);
  }
  if (message.includes("cannot_moderate_self")) {
    return CustomResponse.error("You cannot moderate yourself", EC.PERMISSION_DENIED);
  }
  if (message.includes("cannot_moderate_admin")) {
    return CustomResponse.error("Admins cannot be moderated", EC.PERMISSION_DENIED);
  }
  if (message.includes("user_not_found")) {
    return CustomResponse.error("Member not found", EC.USER_NOT_FOUND);
  }
  return CustomResponse.error("Error moderating member", EC.DB_ERROR, message);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { target_user_id, muted, deafened, banned } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!target_user_id) {
      return CustomResponse.error("Missing required field: target_user_id", EC.MISSING_FIELDS);
    }

    // 1. The row write, with the caller's own JWT so the RPC's app.is_admin()
    //    check applies to them and not to the service role.
    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { error: rpcError } = await asCaller.rpc("moderate_user", {
      p_target: target_user_id,
      p_muted: muted ?? null,
      p_deafened: deafened ?? null,
      p_banned: banned ?? null,
    });

    if (rpcError) return rpcErrorResponse(rpcError.message ?? String(rpcError));

    // 2. Read back the effective state. The request may have set only one flag,
    //    and a permission update replaces all of them at once.
    const { data: targetData, error: targetError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}, ${DBSchema.users.isBanned}`)
      .eq(DBSchema.users.id, target_user_id)
      .single();

    if (targetError || !targetData) {
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND, targetError);
    }

    const target = targetData as Record<string, any>;
    const isMuted: boolean = target[DBSchema.users.isMuted] === true;
    const isDeafened: boolean = target[DBSchema.users.isDeafened] === true;
    const isBanned: boolean = target[DBSchema.users.isBanned] === true;

    // 3. Apply it to whatever they are connected to right now. The row is
    //    already written, so a LiveKit failure must not fail the request —
    //    the moderation still takes effect on their next join. Report it.
    const applied = await applyToLiveRooms(
      auth.serverId,
      target_user_id,
      isMuted,
      isDeafened,
      isBanned,
    );

    return CustomResponse.success({
      muted: isMuted,
      deafened: isDeafened,
      banned: isBanned,
      connections_updated: applied.updated,
      livekit_error: applied.error,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Push the state onto every live connection the target holds on this server.
 *
 * Rooms are named by channel id, so the search space is this server's channels
 * — never every room on a shared LiveKit deployment. A banned member is removed
 * outright; otherwise their permissions and metadata are replaced, and a
 * published microphone is force-muted so existing audio stops immediately.
 *
 * Un-muting deliberately does *not* unmute their track: it restores the
 * permission and leaves turning the mic back on to them.
 */
async function applyToLiveRooms(
  serverId: string,
  targetUserId: string,
  isMuted: boolean,
  isDeafened: boolean,
  isBanned: boolean,
): Promise<{ updated: number; error: string | null }> {
  try {
    const { data: server } = await supabase
      .from(DBSchema.servers.tableName)
      .select(DBSchema.servers.livekitUrl)
      .eq(DBSchema.servers.id, serverId)
      .single();

    const { data: secrets } = await supabase
      .from(DBSchema.serverSecrets.tableName)
      .select(`${DBSchema.serverSecrets.livekitApiKey}, ${DBSchema.serverSecrets.livekitSecretKey}`)
      .eq(DBSchema.serverSecrets.serverId, serverId)
      .single();

    if (!server || !secrets) return { updated: 0, error: "credentials_missing" };

    const secretRecord = secrets as Record<string, any>;
    const apiKey = secretRecord[DBSchema.serverSecrets.livekitApiKey];
    const apiSecret = secretRecord[DBSchema.serverSecrets.livekitSecretKey];
    const livekitUrl: string = (server as Record<string, any>)[DBSchema.servers.livekitUrl] ?? "";
    if (!apiKey || !apiSecret || !livekitUrl) {
      return { updated: 0, error: "credentials_missing" };
    }

    const livekitHost = livekitUrl.replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://");
    const roomService = new RoomServiceClient(livekitHost, apiKey, apiSecret);

    const { data: channels } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, serverId);

    const channelIds = (channels ?? []).map(
      (c) => (c as Record<string, any>)[DBSchema.channels.id] as string,
    );
    if (channelIds.length === 0) return { updated: 0, error: null };

    // Only rooms that actually exist come back, so this is one call rather than
    // one listParticipants per channel on a server where nobody is in voice.
    const rooms = await roomService.listRooms(channelIds);

    const metadata = moderationMetadata(isMuted, isDeafened);
    const permission = livePermissions(isMuted, isDeafened);
    let updated = 0;

    for (const room of rooms) {
      const participants = await roomService.listParticipants(room.name);
      // The identity is "<userId>~<device>", with a "_screenshare" suffix for
      // that device's share. Match on the user id so every device they are on
      // is covered, not just the one a moderator happened to click.
      const mine = participants.filter((p) => p.identity.split("~")[0] === targetUserId);

      for (const participant of mine) {
        if (isBanned) {
          await roomService.removeParticipant(room.name, participant.identity);
          updated++;
          continue;
        }

        await roomService.updateParticipant(room.name, participant.identity, {
          metadata,
          permission,
        });

        if (isMuted) {
          // Revoking the source stops future publishes; this stops the audio
          // already flowing.
          for (const track of participant.tracks ?? []) {
            if (track.source === TrackSource.MICROPHONE && !track.muted) {
              await roomService.mutePublishedTrack(room.name, participant.identity, track.sid, true);
            }
          }
        }
        updated++;
      }
    }

    return { updated, error: null };
  } catch (err) {
    return { updated: 0, error: String(err) };
  }
}
