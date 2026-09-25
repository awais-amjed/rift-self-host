import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import {
  livekitRoomServices,
  releaseVoiceNodes,
  voiceUserId,
} from "../_shared/livekit.ts";

/**
 * Who is in which voice channel on this server, right now: `{userId: channelId}`.
 *
 * Members learn about each other's channel *changes* from broadcasts on
 * `voice:<serverId>`, which is stateless — a client that just opened the app
 * has missed every one of them. This is the snapshot it starts from, and it
 * comes from LiveKit rather than from asking the room, because LiveKit is the
 * only thing that actually knows: a client can lie about where it is, and one
 * that crashed never got to say it left.
 *
 * Readable by any member — being in a call is not a secret from the people who
 * can see the channel list.
 */

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Where a region's load turns from low to medium, and from medium to high,
 * in forwarded streams.
 *
 * Pegged to the one measurement there is: four cores forwarded 2,500 streams
 * with no loss (docs.joinrift.app/sizing/#calls). High starts well short of
 * that, because a box is rarely only a LiveKit and a screen share is worth
 * hundreds of voice streams in bandwidth.
 */
const MEDIUM_FROM = 500;
const HIGH_FROM = 1500;

/**
 * How busy one region is, as a level: `low`, `medium` or `high`.
 *
 * **A level, never a count.** The figure is taken over every room on the node,
 * because a region is as busy as everything on it — private channels, and on
 * a LiveKit shared across a project, other servers' calls. Exact numbers from
 * that let any member see that a call they cannot see had started, and how
 * many were in it. A level says only what choosing a region needs.
 *
 * There is deliberately no `idle`. A region that read idle and then low would
 * announce the first hidden call to start on it; one or two people talking
 * are a handful of streams, and read as low exactly as nobody does.
 *
 * `streams` is what the level is taken from, and the reason heads are not
 * enough: an SFU copies rather than mixes, so the work is publishers ×
 * subscribers. Twenty people listening to nobody is almost free; six people
 * with one screen share between them is not.
 */
function summarise(
  node: { id: string; label: string },
  rooms: { numParticipants: number; numPublishers: number }[],
) {
  let streams = 0;
  for (const room of rooms) {
    const inRoom = room.numParticipants ?? 0;
    const sending = room.numPublishers ?? 0;
    // Each publisher's media goes to everybody else in the room.
    streams += sending * Math.max(inRoom - 1, 0);
  }

  return {
    id: node.id,
    label: node.label,
    load: streams >= HIGH_FROM ? "high" : streams >= MEDIUM_FROM ? "medium" : "low",
    reachable: true,
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const auth = await authenticateToken(supabase, extractBearerToken(req));
    if (isAuthError(auth)) return auth;

    // One admin API per node. A server usually has one, and then this is
    // exactly what it always was; with several, a room lives on one of them
    // and the only way to find out which is to ask each.
    const services = await livekitRoomServices(supabase, auth.serverId);
    if (services.length === 0) {
      return CustomResponse.error(
        "LiveKit credentials not configured for this server",
        EC.SERVER_CREDENTIALS_MISSING,
      );
    }

    // Only the channels this member can see. The roster is `{userId: channelId}`
    // for the whole server, so a private voice channel would otherwise tell
    // everybody who is in a call they cannot join — the membership of the room
    // and, over a day, who talks to whom.
    const { data: channels, error: channelsError } = await supabase.rpc(
      "visible_channels",
      { p_user: auth.userId },
    );
    if (channelsError) {
      return CustomResponse.error("Error reading channels", EC.DB_ERROR, channelsError);
    }

    const channelIds = ((channels ?? []) as Record<string, any>[]).map(
      (c) => c.channel_id as string,
    );
    if (channelIds.length === 0) {
      return CustomResponse.success({ roster: {} });
    }

    // One unfiltered `listRooms` per node, which is both halves of this
    // answer: the roster below, and how busy each region is.
    //
    // Unfiltered because the load is about the *region*, and a region is as
    // busy as everything on it — including channels this caller cannot see.
    // Which is why what goes back is a level and not a count: see summarise.
    //
    // `listRooms` carries `numParticipants` and `numPublishers` per room, so
    // the load costs no request of its own — and skipping `listParticipants`
    // for rooms that are empty or not visible makes this *cheaper* than it
    // was, not dearer.
    const perNode = await Promise.all(
      services.map(async ({ node, service }) => {
        try {
          const rooms = await service.listRooms();

          const visible = rooms.filter(
            (room) => channelIds.includes(room.name) && room.numParticipants > 0,
          );
          const rosters = await Promise.all(
            visible.map(async (room) => {
              try {
                return {
                  room: room.name,
                  participants: await service.listParticipants(room.name),
                };
              } catch {
                return { room: room.name, participants: [] };
              }
            }),
          );

          return { node, rosters, load: summarise(node, rooms) };
        } catch {
          // A node that is down answers with nothing rather than blanking the
          // whole roster. Its calls go missing from the sidebar until it is
          // back, which is what is true — and it reports itself unreachable
          // rather than idle, which is a different thing and the one a
          // manager needs to see.
          return {
            node,
            rosters: [] as { room: string; participants: unknown[] }[],
            load: { id: node.id, label: node.label, load: null, reachable: false },
          };
        }
      }),
    );

    const roster: Record<string, string> = {};
    const busy = new Set<string>();
    for (const { rosters } of perNode) {
      for (const { room, participants } of rosters) {
        if (participants.length > 0) busy.add(room);
        for (const participant of participants as { identity: string }[]) {
          const userId = voiceUserId(participant.identity);
          // Someone joined from two devices in different channels lands here
          // twice; the last room wins, and their own client is the only one that
          // could say which is "theirs". Rare enough to leave alone.
          if (userId) roster[userId] = room;
        }
      }
    }

    // A call that has ended forgets where it was, so the next one on that
    // channel is decided afresh rather than inheriting the first choice the
    // channel ever made. This is the only place that finds out: nothing tells
    // us a room emptied, we notice that it did.
    //
    // Only channels this caller can see, so a member's polling never speaks
    // for a private channel they are not in — a stale row costs a worse
    // choice next time, never a broken call, so being conservative here is
    // free.
    const ended = channelIds.filter((id) => !busy.has(id));
    if (ended.length > 0) {
      await releaseVoiceNodes(supabase, ended).catch(() => {});
    }

    return CustomResponse.success({
      roster,
      regions: perNode.map(({ load }) => load),
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
