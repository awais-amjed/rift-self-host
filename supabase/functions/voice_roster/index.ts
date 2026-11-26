import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import { ParticipantInfo, RoomServiceClient, TrackSource } from "livekit-server-sdk";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { extractBearerToken } from "../_shared/auth.ts";
import { verifyJwt } from "../_shared/jwt.ts";
import { LiveKitNode, normaliseHost, voiceUserId } from "../_shared/livekit.ts";
import { orphanedWatchers, removeWatchers } from "../_shared/watch.ts";

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
 *
 * Also `sharing`: who in those calls has a screen up, so the sidebar can offer
 * to watch it from outside the call. Members say so in their own broadcasts
 * after this; this is where an app that opens mid-stream learns it.
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

/** What one node said: every room, for its load, and this server's rooms' people. */
interface NodeSweep {
  node: LiveKitNode;
  rosters: { room: string; startedAt: number; participants: ParticipantInfo[] }[];
  open: string[];
  reachable: boolean;
  load: ReturnType<typeof summarise> | { id: string; label: string; load: null; reachable: false };
}

/**
 * The last sweep of each server's LiveKit, while this worker lives.
 *
 * Every member's app asks for the roster, and they ask together: everybody
 * opening the server after a restart, and everybody in a call 3 s after
 * somebody in it drops without saying so. Each used to ask every node for
 * every room. One sweep now answers all of them for a moment, and each is
 * handed only the calls they can see, so what a member is told is unchanged.
 * A sweep under way is shared rather than started again.
 */
const sweeps = new Map<string, { at: number; sweep: Promise<NodeSweep[]> }>();
const SWEEP_FOR_MS = 1500;

/**
 * Ask each node for its rooms, and for the people in those of [ownRooms],
 * which are all of this server's voice channels: one sweep answers every
 * member, whatever each may see.
 */
async function sweepNodes(
  services: { node: LiveKitNode; service: RoomServiceClient }[],
  ownRooms: Set<string>,
): Promise<NodeSweep[]> {
  return await Promise.all(
    services.map(async ({ node, service }): Promise<NodeSweep> => {
      try {
        const rooms = await service.listRooms();
        // Every room of this server's, empty-looking or not. LiveKit
        // refreshes a room's `numParticipants` every few seconds (about 5 s
        // on v1.13), so a room somebody has just opened reads 0 and was
        // skipped: whoever looked at the server right then saw the call
        // empty (found Nov 21, review 1). A room that is really empty
        // lingers only until LiveKit's empty timeout, and asking it costs
        // one request that answers nobody.
        const own = rooms.filter((room) => ownRooms.has(room.name));
        const rosters = await Promise.all(
          own.map(async (room) => {
            // When LiveKit created the room: the call's start, for the
            // sidebar's timer. Milliseconds where the server has them,
            // seconds on older ones.
            const startedAt = Number(room.creationTimeMs) ||
              Number(room.creationTime) * 1000;
            try {
              const participants = await service.listParticipants(room.name);
              // A watch connection whose device has left the call goes
              // here: this is read whenever a member looks at the server,
              // and nothing else tells us a room changed (`_shared/watch.ts`).
              // With nobody to remove it costs nothing.
              await removeWatchers(
                service,
                room.name,
                orphanedWatchers(participants.map((p) => p.identity)),
              );
              return { room: room.name, startedAt, participants };
            } catch {
              return { room: room.name, startedAt, participants: [] };
            }
          }),
        );
        // Every room this node holds, whoever is in it: a room LiveKit
        // still lists is a call that has not ended, even one opened a
        // moment ago or one whose participants did not answer.
        return {
          node,
          rosters,
          open: own.map((room) => room.name),
          reachable: true,
          load: summarise(node, rooms),
        };
      } catch {
        // A node that is down answers with nothing rather than blanking the
        // whole roster. Its calls go missing from the sidebar until it is
        // back, which is what is true — and it reports itself unreachable
        // rather than idle, which is a different thing and the one a
        // manager needs to see.
        return {
          node,
          rosters: [],
          open: [],
          reachable: false,
          load: { id: node.id, label: node.label, load: null, reachable: false },
        };
      }
    }),
  );
}

/** [sweepNodes] for [serverId], or the one a moment ago. */
function sweepFor(
  serverId: string,
  services: { node: LiveKitNode; service: RoomServiceClient }[],
  ownRooms: Set<string>,
): Promise<NodeSweep[]> {
  const now = Date.now();
  for (const [key, held] of sweeps) {
    if (now - held.at >= SWEEP_FOR_MS) sweeps.delete(key);
  }
  // The nodes are part of the key: a region added or re-keyed is swept anew.
  const key = `${serverId}|${services.map(({ node }) => `${node.id}@${node.url}`).join(",")}`;
  const held = sweeps.get(key);
  if (held) return held.sweep;
  const sweep = sweepNodes(services, ownRooms);
  sweeps.set(key, { at: now, sweep });
  // A sweep that failed outright is not kept for the next caller.
  sweep.catch(() => sweeps.delete(key));
  return sweep;
}

/**
 * A [RoomServiceClient] per node, from what `voice_roster_facts` answered:
 * the server's own address with its pair when it has no node list, and a
 * region with no key of its own left out, as [livekitRoomServices] does.
 */
function servicesFrom(facts: Record<string, any>) {
  const credentials = facts.credentials as Record<string, string>;
  const rows = (facts.nodes ?? []) as Record<string, any>[];
  const list = rows.length > 0 ? rows : [{
    id: "",
    url: credentials.url,
    label: "Default",
    is_default: true,
    api_key: credentials.api_key,
    api_secret: credentials.api_secret,
  }];
  return list.flatMap((row) => {
    if (!row.api_key || !row.api_secret) return [];
    const node: LiveKitNode = {
      id: row.id,
      url: row.url,
      label: row.label,
      isDefault: row.is_default === true,
    };
    return [{
      node,
      service: new RoomServiceClient(normaliseHost(row.url), row.api_key, row.api_secret),
    }];
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    if (!token) {
      return CustomResponse.error("Missing required field: token", EC.TOKEN_MISSING);
    }
    const userId = await verifyJwt(token);
    if (!userId) {
      return CustomResponse.error("Invalid or expired token", EC.TOKEN_INVALID);
    }

    // Who is asking, the server's nodes and their keys, its voice channels
    // and which of them this member can see, in one call (065).
    const { data: factsData, error: factsError } = await supabase.rpc("voice_roster_facts", {
      p_user: userId,
    });
    if (factsError) {
      return CustomResponse.error("Error reading channels", EC.DB_ERROR, factsError);
    }
    const facts = (factsData ?? {}) as Record<string, any>;
    switch (facts.reason) {
      case "ok":
        break;
      case "user_not_found":
        return CustomResponse.error("User not found", EC.USER_NOT_FOUND);
      case "user_banned":
        return CustomResponse.error("User is banned", EC.USER_BANNED);
      case "credentials_missing":
        return CustomResponse.error(
          "LiveKit credentials not configured for this server",
          EC.SERVER_CREDENTIALS_MISSING,
        );
      default:
        return CustomResponse.error("Error reading channels", EC.DB_ERROR);
    }

    // One admin API per node. A server usually has one, and then this is
    // exactly what it always was; with several, a room lives on one of them
    // and the only way to find out which is to ask each.
    const services = servicesFrom(facts);
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
    const channelIds = (facts.visible ?? []) as string[];
    if (channelIds.length === 0) {
      return CustomResponse.success({ roster: {}, sharing: [] });
    }
    const visibleRooms = new Set(channelIds);

    // One unfiltered `listRooms` per node, which is both halves of this
    // answer: the roster below, and how busy each region is.
    //
    // Unfiltered because the load is about the *region*, and a region is as
    // busy as everything on it — including channels this caller cannot see.
    // Which is why what goes back is a level and not a count: see summarise.
    //
    // `listRooms` carries `numParticipants` and `numPublishers` per room, so
    // the load costs no request of its own. The people are asked for in
    // this server's rooms only, and handed out below for the rooms this
    // member can see.
    const swept = await sweepFor(
      facts.server_id as string,
      services,
      new Set((facts.voice_channels ?? []) as string[]),
    );
    const perNode = swept.map((n) => ({
      ...n,
      rosters: n.rosters.filter((r) => visibleRooms.has(r.room)),
      open: n.open.filter((room) => visibleRooms.has(room)),
    }));

    const roster: Record<string, string> = {};
    const sharing = new Set<string>();
    // Visible, occupied calls only, like the roster: a private channel's
    // start time would say when a call nobody here can join began.
    const started: Record<string, number> = {};
    for (const { rosters } of perNode) {
      for (const { room, startedAt, participants } of rosters) {
        if (participants.length > 0 && startedAt > 0) started[room] = startedAt;
        for (
          const participant of participants as {
            identity: string;
            tracks?: { source?: TrackSource }[];
          }[]
        ) {
          // A desktop's screen is a connection of its own; a phone's rides
          // the one its owner talks on.
          const identity = participant.identity;
          if (
            identity.endsWith("_screenshare") ||
            (participant.tracks ?? []).some((t) => t.source === TrackSource.SCREEN_SHARE)
          ) {
            const owner = identity.split("~")[0];
            if (owner.length > 0) sharing.add(owner);
          }
          const userId = voiceUserId(identity);
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
    //
    // Ended means no node lists a room for it, and the node the call was
    // claimed on answered. A node that did not answer may be holding it, and
    // a room that is there but answered nobody may be one somebody is joining
    // right now: releasing either let the next person in claim the same call
    // on another node, splitting it in two. The database also keeps any row
    // claimed in the last half minute (`release_idle_voice_node`), which
    // covers a room claimed but not yet opened.
    const open = new Set(perNode.flatMap((n) => n.open));
    const candidates = channelIds.filter((id) => !open.has(id));
    if (candidates.length > 0) {
      const answered = new Set(perNode.filter((n) => n.reachable).map((n) => n.node.id));
      const wanted = new Set(candidates);
      const ended = ((facts.claims ?? []) as Record<string, any>[])
        .filter((row) => wanted.has(row.channel_id as string) && answered.has(row.node_id as string))
        .map((row) => row.channel_id as string);
      if (ended.length > 0) {
        await supabase.rpc("release_idle_voice_node", { p_channels: ended })
          .then(({ error }) => {
            if (error) console.error("[voice_roster] release", error);
          });
      }
    }

    return CustomResponse.success({
      roster,
      sharing: [...sharing],
      started,
      regions: perNode.map(({ load }) => load),
    });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});
