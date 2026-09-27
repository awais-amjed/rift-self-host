import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServiceForChannel } from "../_shared/livekit.ts";

/**
 * Ask a bot into a voice channel, or send it away.
 *
 * The authorisation and the row live in `summon_bot_to_voice` /
 * `dismiss_bot_from_voice`, called as the caller so `SUMMON_BOTS` and
 * `app.can_see_channel` are decided about the person who asked.
 *
 * What the RPC cannot do is reach LiveKit, and for dismissing that half is the
 * whole feature. Deleting the summon takes away the bot's media key and its
 * right to a *new* token — and does nothing at all to the connection it already
 * has, which is good for its hour. So "Send away" removed the row, the client
 * said the bot would leave, and the bot stayed in the call publishing music.
 *
 * The same shape as `set_bot_voice_listen`, and for the same reason: a
 * permission that is only true at the next join is not the one anybody meant.
 * `removeParticipant` rather than `updateParticipant` because there is no
 * lesser state to put a summoned bot in — it is in the room or it is not.
 *
 * Summoning pushes nothing. There is no connection yet, and the bot's own poll
 * is what brings it in.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** The RPC's `reason` as a response the client can draw. */
function reasonResponse(reason: string): Response | null {
  switch (reason) {
    case "ok":
      return null;
    case "forbidden":
      return CustomResponse.error("Not allowed to summon bots", EC.PERMISSION_DENIED);
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
    const { bot_id, channel_id, summon } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!bot_id || !channel_id || typeof summon !== "boolean") {
      return CustomResponse.error(
        "Missing required fields: bot_id, channel_id, summon",
        EC.MISSING_FIELDS,
      );
    }

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { data, error } = await asCaller.rpc(
      summon ? "summon_bot_to_voice" : "dismiss_bot_from_voice",
      { p_bot: bot_id, p_channel: channel_id },
    );
    if (error) {
      return CustomResponse.error("Error changing bot voice access", EC.DB_ERROR, error);
    }

    const refusal = reasonResponse((data as Record<string, string>)?.reason ?? "unknown");
    if (refusal) return refusal;

    // The row is written either way; a LiveKit failure must not fail the
    // request, because the bot is already unable to take a new token. Report it
    // so a client can say "sent away, but it is still connected".
    const removed = summon
      ? { updated: 0, error: null }
      : await removeFromLiveRoom(auth.serverId, bot_id, channel_id);

    return CustomResponse.success({
      summon,
      connections_updated: removed.updated,
      livekit_error: removed.error,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Disconnect the bot from the one room it was dismissed from.
 *
 * Scoped to that room, like `set_bot_voice_listen`'s push: a bot summoned into
 * two channels and sent away from one must keep playing in the other.
 */
async function removeFromLiveRoom(
  serverId: string,
  botId: string,
  channelId: string,
): Promise<{ updated: number; error: string | null }> {
  try {
    const roomService = await livekitRoomServiceForChannel(supabase, serverId, channelId);
    if (!roomService) return { updated: 0, error: "credentials_missing" };

    // Rooms are named by channel id. Asking for the one room means an idle
    // channel costs a single call and returns nothing.
    const rooms = await roomService.listRooms([channelId]);
    if (rooms.length === 0) return { updated: 0, error: null };

    const participants = await roomService.listParticipants(channelId);
    const mine = participants.filter((p) => p.identity.split("~")[0] === botId);

    for (const participant of mine) {
      await roomService.removeParticipant(channelId, participant.identity);
    }

    return { updated: mine.length, error: null };
  } catch (err) {
    return { updated: 0, error: String(err) };
  }
}
