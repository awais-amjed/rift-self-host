import { SupabaseClient } from "@supabase/supabase-js";
import { RoomServiceClient } from "livekit-server-sdk";
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
  const { data: server } = await supabase
    .from(DBSchema.servers.tableName)
    .select(DBSchema.servers.livekitUrl)
    .eq(DBSchema.servers.id, serverId)
    .single();

  const { data: secrets } = await supabase
    .from(DBSchema.serverSecrets.tableName)
    .select(`${DBSchema.serverSecrets.livekitApiKey}, ${DBSchema.serverSecrets.livekitSecretKey}`)
    .eq(DBSchema.serverSecrets.serverId, serverId)
    .single();

  if (!server || !secrets) return null;

  const secretRecord = secrets as Record<string, any>;
  const apiKey = secretRecord[DBSchema.serverSecrets.livekitApiKey];
  const apiSecret = secretRecord[DBSchema.serverSecrets.livekitSecretKey];
  const livekitUrl: string = (server as Record<string, any>)[DBSchema.servers.livekitUrl] ?? "";
  if (!apiKey || !apiSecret || !livekitUrl) return null;

  return { host: normaliseHost(livekitUrl), apiKey, apiSecret };
}

/** `wss://` → `https://`, `ws://` → `http://`; anything else is left alone. */
export function normaliseHost(livekitUrl: string): string {
  return livekitUrl.replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://");
}

/**
 * The user behind a LiveKit identity, or null when the connection isn't one.
 *
 * Identities are `<userId>~<deviceId>`, with a `_screenshare` suffix for that
 * device's share. A share is a second connection held by the same person, so
 * anything counting *people* has to drop it — it would double them up in a
 * roster, and telling a screen share to join a channel means nothing.
 */
export function voiceUserId(identity: string): string | null {
  if (identity.endsWith("_screenshare")) return null;
  const userId = identity.split("~")[0];
  return userId.length > 0 ? userId : null;
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
