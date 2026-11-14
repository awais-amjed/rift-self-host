import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServiceForChannel } from "../_shared/livekit.ts";
import { reconcileConnections } from "../_shared/call_rights.ts";

/**
 * Change what one role may do in one channel, and make a voice channel's
 * call agree at once.
 *
 * The rules and the row stay in the `set_channel_override` RPC, called as the
 * caller, so who may change what is decided in one place. Its answer comes
 * back as it came (`{reason}`).
 *
 * What the RPC cannot do is reach LiveKit. Whether someone may speak is minted
 * into their token when they join (`get_channel_token`), so turning a call
 * Listen-only left everyone already talking still talking until they rejoined.
 * After an `ok` on a voice channel this reads `SPEAK` again for everyone in its
 * call and pushes the microphone onto, or off, each connection that has it
 * wrong — off at once, a published microphone muted too, as `moderate_user`
 * does. Given back, the client publishes it again itself, if its own toggle
 * says so.
 *
 * The soundboard moves with it, the same way: a press is a data packet no
 * server sees, so what stops one is the connection's `canPublishData`
 * (`_shared/call_rights.ts`), and that too was minted at the join.
 *
 * Only those two. Connect, sharing and summoning are asked on the next join,
 * share or summon, and nobody is put out of a call they are in.
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
    const { channel_id, role_id, allow, deny } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    if (!channel_id || !role_id || typeof allow !== "number" || typeof deny !== "number") {
      return CustomResponse.error(
        "Missing required fields: channel_id, role_id, allow, deny",
        EC.MISSING_FIELDS,
      );
    }

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );

    const { data, error } = await asCaller.rpc("set_channel_override", {
      p_channel: channel_id,
      p_role: role_id,
      p_allow: allow,
      p_deny: deny,
    });
    if (error) {
      return CustomResponse.error("Error saving the channel's permissions", EC.DB_ERROR, error);
    }

    const reason = (data as Record<string, string>)?.reason ?? "unknown";
    if (reason !== "ok") return CustomResponse.success({ reason });

    // The row is written; a LiveKit failure must not fail the save, since the
    // rule still holds from everyone's next join. Reported, not swallowed.
    const applied = await applyToLiveCall(auth.serverId, channel_id);

    return CustomResponse.success({
      reason,
      connections_updated: applied.updated,
      livekit_error: applied.error,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * Give or take the microphone and the soundboard on every connection in
 * [channelId]'s call that no longer matches (`reconcileConnections`).
 *
 * One room: rooms are named by channel id, and the RPC already said the
 * channel is this server's.
 */
async function applyToLiveCall(
  serverId: string,
  channelId: string,
): Promise<{ updated: number; error: string | null }> {
  try {
    const { data: channel } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.channelType}, ${DBSchema.channels.serverId}`)
      .eq(DBSchema.channels.id, channelId)
      .maybeSingle();
    const row = channel as Record<string, any> | null;
    if (row?.[DBSchema.channels.channelType] !== "voice") return { updated: 0, error: null };
    if (row[DBSchema.channels.serverId] !== serverId) return { updated: 0, error: null };

    const service = await livekitRoomServiceForChannel(supabase, serverId, channelId);
    if (!service) return { updated: 0, error: "credentials_missing" };

    // An idle channel costs one call and answers nothing.
    const rooms = await service.listRooms([channelId]);
    if (rooms.length === 0) return { updated: 0, error: null };

    const connections = await service.listParticipants(channelId);
    const updated = await reconcileConnections(supabase, service, channelId, connections);
    return { updated, error: null };
  } catch (err) {
    return { updated: 0, error: String(err) };
  }
}
