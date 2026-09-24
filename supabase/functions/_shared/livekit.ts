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
 * Loads a server's LiveKit credentials, or null when it has none configured.
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

/**
 * Where this channel's call is, creating that answer if there is not one yet.
 *
 * [preferredNodeId] is what the client measured — a suggestion, checked
 * against the server's own list before it counts for anything. The database
 * decides; see `app.claim_voice_node`, which is one statement so that two
 * people opening the same call at once cannot open it in two places.
 */
export async function claimVoiceNode(
  supabase: SupabaseClient,
  channelId: string,
  preferredNodeId: string | null,
): Promise<LiveKitNode | null> {
  const { data } = await supabase.rpc("claim_voice_node", {
    p_channel: channelId,
    p_preferred: preferredNodeId,
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

  return list.map((node) => ({
    node,
    service: new RoomServiceClient(
      normaliseHost(node.url),
      credentials.apiKey,
      credentials.apiSecret,
    ),
  }));
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
    .select("livekit_nodes(url)")
    .eq("channel_id", channelId)
    .maybeSingle();

  const node = (data as Record<string, any> | null)?.livekit_nodes;
  const url = (Array.isArray(node) ? node[0]?.url : node?.url) ?? credentials.url;

  return new RoomServiceClient(normaliseHost(url), credentials.apiKey, credentials.apiSecret);
}
