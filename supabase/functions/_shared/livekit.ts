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
export async function roomParticipants(
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

/** A [RoomServiceClient] for [serverId], or null when it has no credentials. */
export async function livekitRoomService(
  supabase: SupabaseClient,
  serverId: string,
): Promise<RoomServiceClient | null> {
  const credentials = await livekitCredentials(supabase, serverId);
  if (!credentials) return null;
  return new RoomServiceClient(credentials.host, credentials.apiKey, credentials.apiSecret);
}
