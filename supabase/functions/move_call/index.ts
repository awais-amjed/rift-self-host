import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { DataPacket_Kind, RoomServiceClient } from "livekit-server-sdk";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitCredentials, nodeKeyPair, normaliseHost } from "../_shared/livekit.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  (Deno.env.get("RIFT_SECRET_KEY") ??
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"))!,
);

// Same channel as a move between channels: the client already listens there,
// and both packets say "leave where you are and join again".
const MOVE_TOPIC = "rift.move";
const SIGNAL_VERSION = 1;

/**
 * Move a live call to a different LiveKit node.
 *
 * A room cannot migrate — LiveKit's open-source server binds it to one node —
 * so this is not a server-side relocation. It is the two halves that together
 * look like one: the database is re-pointed, and everybody in the room is told
 * to reconnect. Their next `get_channel_token` reads the new row and sends
 * them to the new node, so they all arrive together.
 *
 * Which is why the old room is left alone rather than deleted. Deleting it
 * would disconnect the room with the same reason a deleted *channel* does, and
 * a client cannot tell those apart — half the call would think it had ended.
 * Left alone it empties as people reconnect, and LiveKit reaps it.
 *
 * Nothing is written down about a call beyond `voice_rooms`, so a caller who
 * loses their connection halfway through leaves the room re-pointed and some
 * people still on the old node. They are not stranded: they are in a working
 * call that the next person to join will not be sent to, and the next
 * `voice_roster` finds them where they are.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, node_id } = await req.json();

    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;

    if (!channel_id || !node_id) {
      return CustomResponse.error(
        "Missing required fields: channel_id, node_id",
        EC.MISSING_FIELDS,
      );
    }

    // Where a call is held is a channel setting, so this asks the question
    // that changes one — `app.can_manage_channel`, for this caller. It asked
    // "admin or channel manager" instead, which is the rule for a public
    // channel only: a private one answers to its own managers, so a server
    // admin who is not in it could move its call, and learn from `moved` how
    // many people were in it.
    //
    // One refusal for both "no such channel" and "not yours", as
    // `get_channel_token` does, so a private channel's id is not confirmed to
    // somebody who cannot see it.
    const { data: manageable, error: manageError } = await supabase.rpc(
      "channel_manageable_by",
      { p_channel: channel_id, p_user: auth.userId },
    );
    if (manageError) {
      return CustomResponse.error("Error reading channel access", EC.DB_ERROR, manageError);
    }
    if (manageable !== true) {
      return CustomResponse.error(
        "Channel not found, or not yours to move",
        EC.PERMISSION_DENIED,
      );
    }

    // On this server, and a voice channel — the ids come from the caller.
    const { data: channelData, error: channelError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}, ${DBSchema.channels.channelType}`)
      .eq(DBSchema.channels.id, channel_id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .single();

    if (channelError || !channelData) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND, channelError);
    }
    if ((channelData as Record<string, any>)[DBSchema.channels.channelType] !== "voice") {
      return CustomResponse.error(
        "Only a voice channel holds a call",
        EC.PERMISSION_DENIED,
      );
    }

    const credentials = await livekitCredentials(supabase, auth.serverId);
    if (!credentials) {
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }

    // Where the call is now, before anything moves it.
    const { data: current } = await supabase
      .from("voice_rooms")
      .select("node_id, livekit_nodes(url, is_default)")
      .eq("channel_id", channel_id)
      .maybeSingle();

    const currentRow = current as Record<string, any> | null;
    if (!currentRow) {
      // Nothing is up. The channel's own setting decides the next call, and
      // this is a no-op rather than an error: the caller asked for the call to
      // be somewhere, and it will be.
      return CustomResponse.success({ moved: 0, reason: "no_call" });
    }
    if (currentRow.node_id === node_id) {
      return CustomResponse.success({ moved: 0, reason: "already_there" });
    }

    const fromNode = Array.isArray(currentRow.livekit_nodes)
      ? currentRow.livekit_nodes[0]
      : currentRow.livekit_nodes;
    const fromUrl = fromNode?.url ?? credentials.url;

    // The region has to be this server's, and it has to answer, *before*
    // anything is written down. Re-pointing first and opening the room second
    // is the obvious order and the wrong one: a region that is offline left
    // `voice_rooms` naming it while everybody carried on in the old room, so
    // the next person to join was sent to a node that was not there — and the
    // mover had been told the move failed.
    const { data: target, error: lookupError } = await supabase
      .from("livekit_nodes")
      .select("id, url, label, is_default")
      .eq("id", node_id)
      .eq("server_id", auth.serverId)
      .maybeSingle();

    const to = target as Record<string, any> | null;
    if (lookupError || !to?.url) {
      return CustomResponse.error(
        "That region is not one of this server's",
        EC.PERMISSION_DENIED,
        lookupError,
      );
    }

    // Opening the room is also how the region is asked whether it is there.
    // Idempotent, the same call `get_channel_token` makes, and it means the
    // first arrival cannot race the second into two rooms of one name.
    // Signed with the *target's* key. Every added region has its own pair,
    // and a client built with the wrong one is refused by the box rather than
    // by anything here — which would read as "the region did not answer".
    const toPair = await nodeKeyPair(
      supabase,
      { id: to.id as string, isDefault: to.is_default === true },
      credentials,
    );
    if (!toPair) {
      return CustomResponse.error(
        `${to.label} has no LiveKit key of its own, so nothing can be opened there`,
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }
    const toService = new RoomServiceClient(
      normaliseHost(to.url),
      toPair.apiKey,
      toPair.apiSecret,
    );
    try {
      await toService.createRoom({ name: channel_id });
    } catch (roomErr) {
      return CustomResponse.error(
        `${to.label} did not answer, so the call was left where it is`,
        EC.UNEXPECTED_ERROR,
        roomErr,
      );
    }

    // Only now is it true. If the packet below fails to reach somebody, they
    // stay in a working call on the old node and the *next* joiner goes to
    // the new one — which is the failure worth having.
    const { data: moved, error: moveError } = await supabase.rpc("move_voice_node", {
      p_channel: channel_id,
      p_node: node_id,
    });
    if (moveError || !(Array.isArray(moved) ? moved[0] : moved)?.url) {
      return CustomResponse.error(
        "Could not record the move",
        EC.UNEXPECTED_ERROR,
        moveError,
      );
    }

    // Everybody on the old node, told to rejoin. `rejoin` rather than `move`
    // because the destination is the channel they are already in: a client
    // reading this drops its cached token — which names the old node — and
    // takes the ordinary join path, which asks where to go.
    const fromPair = await nodeKeyPair(
      supabase,
      currentRow.node_id
        ? {
          id: currentRow.node_id as string,
          isDefault: fromNode?.is_default === true,
        }
        : null,
      credentials,
    );
    const fromService = fromPair
      ? new RoomServiceClient(normaliseHost(fromUrl), fromPair.apiKey, fromPair.apiSecret)
      : null;
    const payload = new TextEncoder().encode(
      JSON.stringify({
        v: SIGNAL_VERSION,
        type: "rejoin",
        channel_id,
        moved_by: auth.userId,
      }),
    );

    let told = 0;
    try {
      // No key for the region they are on means nothing can be said to them.
      // The move is recorded either way, so the next person to ask is sent to
      // the new region; these keep talking where they are until they rejoin.
      const participants = fromService
        ? await fromService.listParticipants(channel_id)
        : [];
      if (participants.length > 0 && fromService) {
        await fromService.sendData(channel_id, payload, DataPacket_Kind.RELIABLE, {
          topic: MOVE_TOPIC,
        });
        told = participants.length;
      }
    } catch {
      // The old node is unreachable, which is a reason to move rather than a
      // reason to stop. The row is already pointing at the new one, so the
      // next person to join opens the call there.
    }

    return CustomResponse.success({
      moved: told,
      from: fromUrl,
      to: to.url,
      region: to.label,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
