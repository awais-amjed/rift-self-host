import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomService } from "../_shared/livekit.ts";

/**
 * Let a bot hear a voice channel, or stop it hearing one.
 *
 * The authorisation and the row live in `grant_bot_voice_listen` /
 * `revoke_bot_voice_listen` (migration 031), called as the caller so
 * `MANAGE_BOTS` and `app.can_see_channel` are decided about the person who
 * clicked rather than about the service role.
 *
 * What the RPC cannot do is reach LiveKit, and that half is the feature. A bot
 * already in the call is holding a token whose grant said `canSubscribe`, and a
 * token is good for its hour no matter what the table says afterwards — so
 * revoking without this push would leave the bot listening for up to an hour
 * while every client drew the light as off. That is exactly the bug
 * `moderate_user` was written to fix for mutes, and it is worth being the same
 * shape twice rather than learning it again.
 *
 * Pushing on *grant* matters less but is not free either: without it a bot that
 * was told to start listening keeps hearing nothing until its token expires,
 * and the admin sees a light that is on and a bot that does not work.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** The RPC's `reason` as a response the dialog can draw. */
function reasonResponse(reason: string): Response | null {
  switch (reason) {
    case "ok":
      return null;
    case "forbidden":
      return CustomResponse.error("Not allowed to manage bots", EC.PERMISSION_DENIED);
    case "no_such_channel":
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    case "not_a_voice_channel":
      return CustomResponse.error("That is not a voice channel", EC.CHANNEL_TYPE_INVALID);
    case "no_such_bot":
      return CustomResponse.error("Bot not found", EC.USER_NOT_FOUND);
    default:
      return CustomResponse.error(`Could not change bot voice access: ${reason}`, EC.DB_ERROR);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { bot_id, channel_id, listen } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!bot_id || !channel_id || typeof listen !== "boolean") {
      return CustomResponse.error(
        "Missing required fields: bot_id, channel_id, listen",
        EC.MISSING_FIELDS,
      );
    }

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { data, error } = await asCaller.rpc(
      listen ? "grant_bot_voice_listen" : "revoke_bot_voice_listen",
      { p_bot: bot_id, p_channel: channel_id },
    );
    if (error) {
      return CustomResponse.error("Error changing bot voice access", EC.DB_ERROR, error);
    }

    const refusal = reasonResponse((data as Record<string, string>)?.reason ?? "unknown");
    if (refusal) return refusal;

    // The row is written either way; a LiveKit failure must not fail the
    // request, because the new permission still applies at the bot's next join.
    // Report it instead of swallowing it, so a dialog can say "granted, but it
    // will not take effect until the bot rejoins".
    const applied = await applyToLiveRoom(auth.serverId, bot_id, channel_id, listen);

    return CustomResponse.success({
      listen,
      connections_updated: applied.updated,
      livekit_error: applied.error,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Push the new subscription permission onto the bot's live connection.
 *
 * Scoped to the one room, unlike `moderate_user`'s sweep: this grant is about
 * a single channel, and a bot listening in another one it was granted
 * separately must not be disconnected because this one was revoked.
 *
 * `updateParticipant` replaces the whole permission set atomically, so every
 * field has to be stated — omitting one clears it. A bot is never deafened or
 * muted by the moderation flags (nothing offers that for a bot), so the only
 * moving part is `canSubscribe`.
 */
async function applyToLiveRoom(
  serverId: string,
  botId: string,
  channelId: string,
  listen: boolean,
): Promise<{ updated: number; error: string | null }> {
  try {
    const roomService = await livekitRoomService(supabase, serverId);
    if (!roomService) return { updated: 0, error: "credentials_missing" };

    // Rooms are named by channel id. Asking for the one room means an idle
    // channel costs a single call and returns nothing.
    const rooms = await roomService.listRooms([channelId]);
    if (rooms.length === 0) return { updated: 0, error: null };

    const participants = await roomService.listParticipants(channelId);
    const mine = participants.filter((p) => p.identity.split("~")[0] === botId);

    for (const participant of mine) {
      await roomService.updateParticipant(channelId, participant.identity, {
        permission: {
          canSubscribe: listen,
          canPublish: true,
          canPublishData: true,
          // Empty list means every source, the opposite encoding to an
          // AccessToken grant's `undefined` — see `_shared/moderation.ts`.
          canPublishSources: [],
        },
      });
    }

    return { updated: mine.length, error: null };
  } catch (err) {
    return { updated: 0, error: String(err) };
  }
}
