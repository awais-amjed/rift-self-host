import { SupabaseClient } from "@supabase/supabase-js";
import { ParticipantInfo, RoomServiceClient } from "livekit-server-sdk";
import DBSchema from "./schema.ts";

/**
 * A server's LiveKit admin credentials.
 *
 * [host] is the stored `wss://` / `ws://` URL normalised to the `https://` /
 * `http://` form the admin API wants — the client connects over WebSocket, the
 * API is plain HTTP, and they are the same deployment.
 */
export interface LiveKitCredentials {
  host: string;
  apiKey: string;
  apiSecret: string;

  /**
   * The stored `wss://` URL, unchanged — what a *client* connects to, where
   * [host] is the `https://` form the admin API wants.
   *
   * Handed back to the client with its token rather than read from
   * `servers.livekit_url` on the client side, so that which LiveKit a channel
   * lives on is decided here. Today every channel on a server answers with the
   * same address; the point is that a client asking for a token is already
   * being told where to take it, so moving a channel to a different node
   * later is a server-side change rather than one every installed client has
   * to be updated for.
   */
  url: string;
}

/**
 * Loads a server's own LiveKit credentials, or null when it has none
 * configured.
 *
 * The default node's pair, and the fallback for every region that has not
 * been given one of its own — see [nodeKeyPair].
 *
 * The API secret lives in `server_secrets`, which no client can read — needing
 * it is the whole reason an operation is an edge function rather than a table
 * call, and every one of those (mint a token, delete a room, moderate, move)
 * started by writing out this same pair of selects.
 */
export async function livekitCredentials(
  supabase: SupabaseClient,
  serverId: string,
): Promise<LiveKitCredentials | null> {
  // Two rows in two tables, neither waiting on the other. Minting a join
  // token is on the path of every call, so the round trip saved here is one
  // every member pays every time they join one.
  const [{ data: server }, { data: secrets }] = await Promise.all([
    supabase
      .from(DBSchema.servers.tableName)
      .select(DBSchema.servers.livekitUrl)
      .eq(DBSchema.servers.id, serverId)
      .single(),
    supabase
      .from(DBSchema.serverSecrets.tableName)
      .select(`${DBSchema.serverSecrets.livekitApiKey}, ${DBSchema.serverSecrets.livekitSecretKey}`)
      .eq(DBSchema.serverSecrets.serverId, serverId)
      .single(),
  ]);

  if (!server || !secrets) return null;

  const secretRecord = secrets as Record<string, any>;
  const apiKey = secretRecord[DBSchema.serverSecrets.livekitApiKey];
  const apiSecret = secretRecord[DBSchema.serverSecrets.livekitSecretKey];
  const livekitUrl: string = (server as Record<string, any>)[DBSchema.servers.livekitUrl] ?? "";
  if (!apiKey || !apiSecret || !livekitUrl) return null;

  return { host: normaliseHost(livekitUrl), apiKey, apiSecret, url: livekitUrl };
}

/** `wss://` → `https://`, `ws://` → `http://`; anything else is left alone. */
export function normaliseHost(livekitUrl: string): string {
  return livekitUrl.replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://");
}

/**
 * The user behind a LiveKit identity, or null when the connection isn't one.
 *
 * Identities are `<userId>~<deviceId>`, with a `_screenshare` or `_soundshare`
 * suffix for that device's screen or sound share. A share is a second
 * connection held by the same person, so anything counting *people* has to
 * drop it — it would double them up in a roster, and telling a screen share to
 * join a channel means nothing.
 */
export function voiceUserId(identity: string): string | null {
  if (identity.endsWith("_screenshare") || identity.endsWith("_soundshare")) return null;
  const userId = identity.split("~")[0];
  return userId.length > 0 ? userId : null;
}

/** One room's live participants, as [roomParticipants] returns them. */
export interface RoomRoster {
  room: string;
  participants: ParticipantInfo[];
}

/**
 * Who is in each of [rooms], asked all at once.
 *
 * LiveKit has no "participants in these rooms" call, so there is one request
 * per room either way — but awaiting them in a loop makes the answer as slow
 * as the sum of them, and every caller here is either a member opening a
 * server or a moderator waiting on a click. A server with twenty busy voice
 * channels paid twenty round trips in series; it now pays the slowest one.
 *
 * A room that fails to answer comes back empty rather than throwing. The
 * rooms are independent: one unreachable channel should not blank a whole
 * roster, and for a kick or a move it means one place not searched rather
 * than a refusal the moderator has to interpret.
 */
async function roomParticipants(
  roomService: RoomServiceClient,
  rooms: { name: string }[],
): Promise<RoomRoster[]> {
  return await Promise.all(
    rooms.map(async (room) => {
      try {
        return { room: room.name, participants: await roomService.listParticipants(room.name) };
      } catch {
        return { room: room.name, participants: [] };
      }
    }),
  );
}


// ── More than one LiveKit ───────────────────────────────────

/** One of a server's LiveKit nodes. */
export interface LiveKitNode {
  id: string;
  url: string;
  label: string;
}

/** A LiveKit API key and secret, whoever they belong to. */
export interface KeyPair {
  apiKey: string;
  apiSecret: string;
}

/**
 * The key pair each of [nodeIds] signs with, for those that have their own.
 *
 * A node without a row here uses the server's pair, which is why the map is
 * allowed to come back short — and why every caller below reads it with a
 * fallback rather than treating a miss as a failure.
 *
 * Its own table (`livekit_node_secrets`) with no policy and no grant, read
 * here on the service role. One key per node rather than one per server
 * because the key is *on* every box it belongs to: a shared pair means the
 * cheapest VPS in the list can mint tokens for the room on any other node,
 * including the one the server itself runs on.
 */
export async function nodeKeyPairs(
  supabase: SupabaseClient,
  nodeIds: string[],
): Promise<Map<string, KeyPair>> {
  const wanted = nodeIds.filter((id) => id.length > 0);
  if (wanted.length === 0) return new Map();

  const { data } = await supabase
    .from("livekit_node_secrets")
    .select("node_id, livekit_api_key, livekit_secret_key")
    .in("node_id", wanted);

  const pairs = new Map<string, KeyPair>();
  for (const row of (data ?? []) as Record<string, any>[]) {
    if (!row.livekit_api_key || !row.livekit_secret_key) continue;
    pairs.set(row.node_id, {
      apiKey: row.livekit_api_key,
      apiSecret: row.livekit_secret_key,
    });
  }
  return pairs;
}

/**
 * The pair one node signs with: its own when it has one, the server's when it
 * doesn't — which is always the answer for the default node, and for every
 * node on a server that has not given any of them a key.
 */
export async function nodeKeyPair(
  supabase: SupabaseClient,
  nodeId: string | null,
  fallback: KeyPair,
): Promise<KeyPair> {
  if (!nodeId) return fallback;
  return (await nodeKeyPairs(supabase, [nodeId])).get(nodeId) ?? fallback;
}

/**
 * Where this channel's call is, creating that answer if there is not one yet.
 *
 * [preferredNodeId] is what the client measured — a suggestion, checked
 * against the server's own list before it counts for anything. The database
 * decides; see `app.claim_voice_node`, which is one statement so that two
 * people opening the same call at once cannot open it in two places.
 *
 * [ignorePin] is for the second attempt, after the pinned region has been
 * found unreachable. It changes this call only — the pin stays in the
 * channel's row, and the next call tries it again.
 */
export async function claimVoiceNode(
  supabase: SupabaseClient,
  channelId: string,
  preferredNodeId: string | null,
  ignorePin = false,
): Promise<LiveKitNode | null> {
  const { data } = await supabase.rpc("claim_voice_node", {
    p_channel: channelId,
    p_preferred: preferredNodeId,
    p_ignore_pin: ignorePin,
  });
  const row = Array.isArray(data) ? data[0] : data;
  if (!row?.id || !row?.url) return null;
  return { id: row.id, url: row.url, label: row.label ?? "" };
}

/**
 * Forget where these channels' calls were, because they have ended.
 *
 * Called by `voice_roster`, the one thing that asks every node who is in each
 * room and therefore the only thing that finds out. Late is fine: a row left
 * behind sends the next caller to a node with no such room, and LiveKit makes
 * one there.
 */
export async function releaseVoiceNodes(
  supabase: SupabaseClient,
  channelIds: string[],
): Promise<void> {
  if (channelIds.length === 0) return;
  await supabase.rpc("release_voice_node", { p_channels: channelIds });
}

/** Every LiveKit this server may hold a call on, default first. */
export async function livekitNodes(
  supabase: SupabaseClient,
  serverId: string,
): Promise<LiveKitNode[]> {
  const { data } = await supabase
    .from("livekit_nodes")
    .select("id, url, label, is_default")
    .eq("server_id", serverId)
    .order("is_default", { ascending: false })
    .order("label");
  return (data ?? []).map((n: Record<string, any>) => ({
    id: n.id,
    url: n.url,
    label: n.label,
  }));
}

/**
 * A [RoomServiceClient] per node, for the operations that have to find a room
 * without being told where it is — a kick, a move, a roster.
 *
 * One server used to mean one admin API, so those functions took a single
 * client and asked it. With a room per node, "who is in this channel" is a
 * question for whichever node is holding it, and the cheap way to stay
 * correct is to ask all of them: a node that is not holding the room answers
 * empty, which is the same answer as a room nobody is in.
 */
export async function livekitRoomServices(
  supabase: SupabaseClient,
  serverId: string,
): Promise<{ node: LiveKitNode; service: RoomServiceClient }[]> {
  const credentials = await livekitCredentials(supabase, serverId);
  if (!credentials) return [];

  const nodes = await livekitNodes(supabase, serverId);
  // A server whose node list has not been read (or a database from before
  // there was one) still has the address on `servers` — the same node under
  // its other name.
  const list: LiveKitNode[] = nodes.length > 0
    ? nodes
    : [{ id: "", url: credentials.url, label: "Default" }];

  // One query for the whole list, not one per node: this runs on every
  // roster, kick and move, and each of those already asks every node a
  // question of its own.
  const pairs = await nodeKeyPairs(supabase, list.map((node) => node.id));

  return list.map((node) => {
    const { apiKey, apiSecret } = pairs.get(node.id) ?? credentials;
    return {
      node,
      service: new RoomServiceClient(normaliseHost(node.url), apiKey, apiSecret),
    };
  });
}

/**
 * Who is in each of [rooms], asked of every node.
 *
 * The same answer shape as [roomParticipants], merged: a room lives on one
 * node, so at most one of them answers with anybody in it. Which node that
 * was comes back too, because the caller usually wants to act on the room
 * next and needs to know where to send the instruction.
 */
export async function roomParticipantsAcross(
  services: { node: LiveKitNode; service: RoomServiceClient }[],
  rooms: { name: string }[],
): Promise<(RoomRoster & { node: LiveKitNode; service: RoomServiceClient })[]> {
  const perNode = await Promise.all(
    services.map(async ({ node, service }) => {
      const rosters = await roomParticipants(service, rooms);
      return rosters.map((r) => ({ ...r, node, service }));
    }),
  );

  // One row per room: the node that has people in it, or the first node's
  // empty answer so that every room is still represented.
  const byRoom = new Map<string, RoomRoster & { node: LiveKitNode; service: RoomServiceClient }>();
  for (const roster of perNode.flat()) {
    const held = byRoom.get(roster.room);
    if (!held || (held.participants.length === 0 && roster.participants.length > 0)) {
      byRoom.set(roster.room, roster);
    }
  }
  return [...byRoom.values()];
}

/**
 * The admin API for the node holding [channelId]'s call.
 *
 * For the operations that act on one known channel — deleting its room,
 * moving a bot in or out. Cheaper than [livekitRoomServices] because there is
 * nothing to search: `voice_rooms` already says where the call is.
 *
 * Falls back to the server's own address when there is no live call, which is
 * the right answer for a room that is about to be created and harmless for
 * one being deleted: deleting a room that is not there succeeds quietly.
 */
export async function livekitRoomServiceForChannel(
  supabase: SupabaseClient,
  serverId: string,
  channelId: string,
): Promise<RoomServiceClient | null> {
  const credentials = await livekitCredentials(supabase, serverId);
  if (!credentials) return null;

  const { data } = await supabase
    .from("voice_rooms")
    .select("node_id, livekit_nodes(url)")
    .eq("channel_id", channelId)
    .maybeSingle();

  const row = data as Record<string, any> | null;
  const node = row?.livekit_nodes;
  const url = (Array.isArray(node) ? node[0]?.url : node?.url) ?? credentials.url;
  // The node's own key when it has one. A channel with no live call falls
  // back to the server's address *and* the server's pair, which belong
  // together: that address is the default node's.
  const { apiKey, apiSecret } = await nodeKeyPair(
    supabase,
    (row?.node_id as string | null) ?? null,
    credentials,
  );

  return new RoomServiceClient(normaliseHost(url), apiKey, apiSecret);
}
