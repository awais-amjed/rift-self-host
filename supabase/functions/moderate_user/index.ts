import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { TrackSource } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServices, roomParticipantsAcross } from "../_shared/livekit.ts";
import { livePermissions, micDenied, moderationMetadata } from "../_shared/moderation.ts";

/**
 * Server-side mute / deafen / ban / kick.
 *
 * The authorisation and the row write stay in the `moderate_user` RPC — this
 * calls it as the caller, so the "`BAN_MEMBERS` to ban, not yourself, not an
 * admin, not another who can ban" rules live in one place. What the RPC cannot do is reach LiveKit:
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
 *
 * A kick (`kicked: true`, alone) goes through `kick_member` instead, which has
 * its own permission, `KICK_MEMBERS`. To LiveKit it is a ban: the row says
 * `is_banned` until an invite brings them back, so they are removed outright.
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
  if (message.includes("cannot_ban_peer")) {
    return CustomResponse.error("Somebody who can ban cannot be banned", EC.PERMISSION_DENIED);
  }
  if (message.includes("cannot_kick_peer")) {
    return CustomResponse.error("Somebody who can kick or ban cannot be kicked", EC.PERMISSION_DENIED);
  }
  if (message.includes("cannot_kick_bot")) {
    return CustomResponse.error("A bot is removed from Bots, not kicked", EC.PERMISSION_DENIED);
  }
  if (message.includes("user_banned")) {
    return CustomResponse.error("They are already banned", EC.USER_BANNED);
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
    const { target_user_id, muted, deafened, banned, kicked } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!target_user_id) {
      return CustomResponse.error("Missing required field: target_user_id", EC.MISSING_FIELDS);
    }

    // 1. The row write, with the caller's own JWT so the RPC's permission
    //    check applies to them and not to the service role.
    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { error: rpcError } = kicked === true
      ? await asCaller.rpc("kick_member", { p_target: target_user_id })
      : await asCaller.rpc("moderate_user", {
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
      .select(
        `${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}, ${DBSchema.users.isBanned}, ` +
          DBSchema.users.kickedAt,
      )
      .eq(DBSchema.users.id, target_user_id)
      .single();

    if (targetError || !targetData) {
      return CustomResponse.error("Member not found", EC.USER_NOT_FOUND, targetError);
    }

    const target = targetData as Record<string, any>;
    const isMuted: boolean = target[DBSchema.users.isMuted] === true;
    const isDeafened: boolean = target[DBSchema.users.isDeafened] === true;
    const isBanned: boolean = target[DBSchema.users.isBanned] === true;
    const isKicked: boolean = target[DBSchema.users.kickedAt] != null;

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
      kicked: isKicked,
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
    // One admin API per node: a muted member has to stay muted whichever
    // LiveKit the call they are in happens to be on.
    const services = await livekitRoomServices(supabase, serverId);
    if (services.length === 0) return { updated: 0, error: "credentials_missing" };

    const { data: channels } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, serverId);

    const channelIds = (channels ?? []).map(
      (c) => (c as Record<string, any>)[DBSchema.channels.id] as string,
    );
    if (channelIds.length === 0) return { updated: 0, error: null };

    // Only rooms that actually exist come back, so this is one call per node
    // rather than one listParticipants per channel on a server where nobody
    // is in voice.
    // A ban reaches their DM calls too (`dm-<callId>`), which no channel id
    // names. Only a ban: a moderator's voice mute is about the server's
    // channels, and a call between two people is not one of them — it was
    // never minted with the flags (`get_dm_call_token`), so it is not updated
    // with them either.
    const rooms = (await Promise.all(
      services.map(async ({ service }) => {
        try {
          const channelRooms = await service.listRooms(channelIds);
          if (!isBanned) return channelRooms;
          const callRooms = (await service.listRooms())
            .filter((room) => room.name.startsWith("dm-"));
          return [...channelRooms, ...callRooms];
        } catch {
          return [];
        }
      }),
    )).flat();

    const metadata = moderationMetadata(isMuted, isDeafened);
    const permission = livePermissions(isMuted, isDeafened);

    // The identity is "<userId>~<device>", with a "_screenshare" suffix for
    // that device's share. Match on the user id so every device they are on
    // is covered, not just the one a moderator happened to click.
    const mine = (await roomParticipantsAcross(services, rooms)).flatMap(
      ({ room, participants, service }) =>
        participants
          .filter((p) => p.identity.split("~")[0] === targetUserId)
          .map((participant) => ({ room, participant, service }))
    );

    // Across connections at once — they are different rooms or different
    // devices, and a moderator is waiting on this. *Within* one connection the
    // order still holds: the permission change has to land before the mute,
    // because the first stops the next publish and the second stops the audio
    // already flowing. Reversed, a track muted first can be raised again by
    // the client before its permission is gone.
    await Promise.all(
      mine.map(async ({ room, participant, service }) => {
        if (isBanned) {
          await service.removeParticipant(room, participant.identity);
          return;
        }

        await service.updateParticipant(room, participant.identity, {
          metadata,
          permission,
        });

        if (micDenied(isMuted, isDeafened)) {
          await Promise.all(
            (participant.tracks ?? [])
              .filter((track) => track.source === TrackSource.MICROPHONE && !track.muted)
              .map((track) =>
                service.mutePublishedTrack(room, participant.identity, track.sid, true)
              ),
          );
        }
      }),
    );

    return { updated: mine.length, error: null };
  } catch (err) {
    return { updated: 0, error: String(err) };
  }
}
