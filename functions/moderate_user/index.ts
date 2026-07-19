import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { RoomServiceClient, TrackSource } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Server-side moderation: persistently mute/unmute/deafen/undeafen a user.
 *
 * The flags are stored on the users row (source of truth) and enforced in
 * get_channel_token, so they survive rejoins, reconnects, and channel hops
 * and cannot be reverted client-side. If the target is currently in a voice
 * channel, the new permissions and metadata are applied live via LiveKit's
 * RoomService — the mic track is force-unpublished immediately and every
 * client sees the state change through participant metadata.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { user_id, is_muted, is_deafened } = await req.json();
    const token = extractBearerToken(req);

    if (!user_id || (is_muted === undefined && is_deafened === undefined)) {
      return CustomResponse.error(
        "Missing required fields: user_id and at least one of is_muted, is_deafened",
        EC.MISSING_FIELDS,
      );
    }

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!auth.isChannelManager && !auth.isServerAdmin) {
      return CustomResponse.error(
        "Unauthorized: Only channel managers and server admins can moderate users",
        EC.PERMISSION_DENIED,
      );
    }

    // Fetch the target — must exist on this server and must not be an admin.
    const { data: targetData, error: targetError } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.isServerAdmin}, ${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}`,
      )
      .eq(DBSchema.users.id, user_id)
      .eq(DBSchema.users.serverId, auth.serverId)
      .single();

    if (targetError || !targetData) {
      return CustomResponse.error("User not found", EC.USER_NOT_FOUND, targetError);
    }

    const target = targetData as Record<string, any>;
    if (target[DBSchema.users.isServerAdmin]) {
      return CustomResponse.error(
        "Unauthorized: Server admins cannot be moderated",
        EC.PERMISSION_DENIED,
      );
    }

    const muted: boolean =
      is_muted !== undefined ? is_muted === true : target[DBSchema.users.isMuted];
    const deafened: boolean =
      is_deafened !== undefined ? is_deafened === true : target[DBSchema.users.isDeafened];

    // 1. Persist — the source of truth enforced by get_channel_token.
    const { error: updateError } = await supabase
      .from(DBSchema.users.tableName)
      .update({
        [DBSchema.users.isMuted]: muted,
        [DBSchema.users.isDeafened]: deafened,
      })
      .eq(DBSchema.users.id, user_id);

    if (updateError) {
      return CustomResponse.error("Error updating moderation state", EC.DB_ERROR, updateError);
    }

    // 2. Live-apply if the user is currently in a voice channel. Best-effort:
    // if this fails the persisted flags still take effect on the next token.
    const { data: server } = await supabase
      .from(DBSchema.servers.tableName)
      .select(
        `${DBSchema.servers.livekitUrl}, ${DBSchema.servers.livekitApiKey}, ${DBSchema.servers.livekitSecretKey}`,
      )
      .eq(DBSchema.servers.id, auth.serverId)
      .single();

    const serverRecord = (server ?? {}) as Record<string, any>;
    const livekitUrl: string = serverRecord[DBSchema.servers.livekitUrl] ?? "";
    const apiKey = serverRecord[DBSchema.servers.livekitApiKey];
    const apiSecret = serverRecord[DBSchema.servers.livekitSecretKey];

    let appliedLive = false;
    if (livekitUrl && apiKey && apiSecret) {
      const livekitHost = livekitUrl
        .replace(/^wss:\/\//, "https://")
        .replace(/^ws:\/\//, "http://");
      const roomService = new RoomServiceClient(livekitHost, apiKey, apiSecret);

      // Rooms are channel ids — find the one the user is in.
      const { data: channels } = await supabase
        .from(DBSchema.channels.tableName)
        .select(DBSchema.channels.id)
        .eq(DBSchema.channels.serverId, auth.serverId);

      for (const channel of (channels ?? []) as Record<string, any>[]) {
        const room = channel[DBSchema.channels.id] as string;
        try {
          const participants = await roomService.listParticipants(room);
          // Identities are `<userId>~<deviceId>` (get_channel_token), with a
          // `_screenshare` suffix for screenshare sessions — match every
          // session belonging to the target, across all rooms (a user's
          // devices may sit in different channels).
          const sessions = participants.filter(
            (p) => p.identity === user_id || p.identity.startsWith(`${user_id}~`),
          );
          for (const session of sessions) {
            await roomService.updateParticipant(
              room,
              session.identity,
              JSON.stringify({ muted, deafened }),
              {
                canSubscribe: !deafened,
                canPublish: true,
                canPublishData: true,
                // Empty list = all sources allowed.
                canPublishSources: muted
                  ? [TrackSource.CAMERA, TrackSource.SCREEN_SHARE, TrackSource.SCREEN_SHARE_AUDIO]
                  : [],
                hidden: false,
                canUpdateMetadata: false,
              },
            );
            appliedLive = true;
          }
        } catch (_) {
          // Room doesn't exist or is empty — keep looking.
        }
      }
    }

    return CustomResponse.success({
      user_id,
      is_muted: muted,
      is_deafened: deafened,
      applied_live: appliedLive,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
