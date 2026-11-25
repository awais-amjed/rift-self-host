import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServiceForChannel, livekitRoomServices } from "../_shared/livekit.ts";
import { connectionsOutside } from "../_shared/call_rights.ts";

/**
 * Change who is in a private channel, or leave one, and take whoever is no
 * longer in it out of the call running there.
 *
 * Two shapes:
 *   * `{channel_id, add, remove}` — a manager's change, by name, through the
 *     `change_channel_members` RPC (042): only the people named are touched.
 *   * `{channel_id, leave: true}` — the caller walks out, through
 *     `leave_channel`, which needs nobody's permission.
 *
 * Both RPCs run as the caller, so who may change what is decided in one place,
 * and their answer comes back as it came (`{reason}`).
 *
 * What an RPC cannot do is reach LiveKit. A seat is checked when somebody
 * joins a call (`get_channel_token`), never again, so a member removed from a
 * private voice channel kept hearing it until they hung up, and the confirm
 * had promised they would see nothing after. After an `ok` this asks the
 * database, for everyone in the channel's call, whether they may still be in
 * it (`channel_joinable_by`, as `get_channel_token` asks), and removes every connection of anybody who
 * cannot, screen share included, as `kick_user` does. When the last seat went
 * and the channel with it (`reassign_or_close_channel`), the room is deleted,
 * as `delete_channel` does.
 *
 * The LiveKit half never fails the change: the seats are what decide, and a
 * LiveKit that cannot be reached is reported back as `livekit_error`.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, add, remove, leave } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const leaving = leave === true;
    // One or the other: with both, leaving quietly won and the change asked
    // for beside it never happened.
    if (leaving && (add !== undefined || remove !== undefined)) {
      return CustomResponse.error(
        "Send leave on its own, or add and remove without it",
        EC.MISSING_FIELDS,
      );
    }
    if (
      !channel_id ||
      (!leaving && (!isIdList(add ?? []) || !isIdList(remove ?? [])))
    ) {
      return CustomResponse.error(
        "Missing required fields: channel_id, and add and remove as lists of ids or leave",
        EC.MISSING_FIELDS,
      );
    }

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { data, error } = leaving
      ? await asCaller.rpc("leave_channel", { p_channel: channel_id })
      : await asCaller.rpc("change_channel_members", {
        p_channel: channel_id,
        p_add: add ?? [],
        p_remove: remove ?? [],
      });
    if (error) {
      if (error.message === "not_authorized") {
        return CustomResponse.error(
          "Only whoever runs this channel can change who is in it",
          EC.PERMISSION_DENIED,
        );
      }
      return CustomResponse.error("Error changing who is in the channel", EC.DB_ERROR, error);
    }

    const reason = (data as Record<string, string>)?.reason ?? "unknown";
    if (reason !== "ok") return CustomResponse.success({ reason });

    const applied = await applyToLiveCall(auth.serverId, channel_id);
    return CustomResponse.success({
      reason,
      connections_removed: applied.removed,
      livekit_error: applied.error,
    });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});

function isIdList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

/**
 * Take everybody who can no longer see [channelId] out of its call, or end
 * the call when the channel itself went. Never throws.
 */
async function applyToLiveCall(
  serverId: string,
  channelId: string,
): Promise<{ removed: number; error: string | null }> {
  try {
    const { data: channel, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.channelType}, ${DBSchema.channels.serverId}`)
      .eq(DBSchema.channels.id, channelId)
      .maybeSingle();
    if (channelError) {
      console.error("[change_channel_members]", channelError);
      return { removed: 0, error: "db_error" };
    }
    const row = channel as Record<string, any> | null;
    if (row && row[DBSchema.channels.serverId] !== serverId) return { removed: 0, error: null };
    if (row && row[DBSchema.channels.channelType] !== "voice") return { removed: 0, error: null };

    // The last seat took the channel with it: nobody may be in its call.
    // Asked of every node: the row that said where the call was went with
    // the channel, so the one node it would name now is the default, and a
    // call held in another region would have gone on.
    if (!row) {
      const services = await livekitRoomServices(supabase, serverId);
      if (services.length === 0) return { removed: 0, error: "credentials_missing" };
      // No room is the usual answer on each: nobody was in a call there.
      await Promise.allSettled(services.map(({ service }) => service.deleteRoom(channelId)));
      return { removed: 0, error: null };
    }

    const service = await livekitRoomServiceForChannel(supabase, serverId, channelId);
    if (!service) return { removed: 0, error: "credentials_missing" };

    const rooms = await service.listRooms([channelId]);
    if (rooms.length === 0) return { removed: 0, error: null };
    const connections = await service.listParticipants(channelId);

    const toRemove = await connectionsOutside(supabase, channelId, connections);
    // Each on its own: one connection that left in the meantime must not
    // keep the rest in the call.
    const results = await Promise.allSettled(
      toRemove.map((p) => service.removeParticipant(channelId, p.identity)),
    );
    const failed = results.filter((r) => r.status === "rejected");
    for (const r of failed) console.error("[livekit]", (r as PromiseRejectedResult).reason);
    return {
      removed: toRemove.length - failed.length,
      error: failed.length > 0 ? "livekit_unreachable" : null,
    };
  } catch (err) {
    console.error("[livekit]", err);
    return { removed: 0, error: "livekit_unreachable" };
  }
}
