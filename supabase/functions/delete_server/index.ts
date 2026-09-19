import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomService } from "../_shared/livekit.ts";

/**
 * Delete a server: everything it holds, and everything holding it up.
 *
 * The row delete is the `delete_server` RPC, run with the caller's own JWT so
 * the database is what decides — it refuses anyone but the owner (migration
 * 013) and cascades to every table the server owns. What the cascade cannot
 * reach is done here with the service role, after the RPC has said yes:
 *
 *   * the LiveKit room of every voice channel, which disconnects whoever is
 *     still in one — the same reason `delete_channel` is an edge function;
 *   * the `chat-<serverId>` attachment bucket, which `storage.protect_delete()`
 *     keeps out of reach of every database role;
 *   * each member's avatar, in the shared `avatars` bucket.
 *
 * Every one of those is best-effort and reported back, not swallowed: a
 * LiveKit that cannot be reached must not leave the owner with a server that
 * will not go away, and a storage object that outlives its server is a leak,
 * not a breach — the bucket's policies were keyed on a membership that no
 * longer exists.
 */
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const AVATARS_BUCKET = "avatars";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Gathered before the cascade takes them, used only after it has run.
    const leftovers = await collectLeftovers(auth.serverId);

    const asCaller = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const { data: deletedId, error: rpcError } = await asCaller.rpc("delete_server");
    if (rpcError) {
      const message = rpcError.message ?? String(rpcError);
      if (message.includes("not_owner")) {
        return CustomResponse.error("Only the owner can delete a server", EC.PERMISSION_DENIED);
      }
      return CustomResponse.error("Error deleting server", EC.DB_ERROR, message);
    }
    if (deletedId !== auth.serverId) {
      return CustomResponse.error("Server not found", EC.SERVER_NOT_FOUND);
    }

    const errors: Record<string, string> = {};
    const roomError = await deleteRooms(auth.serverId, leftovers.voiceChannelIds);
    if (roomError) errors.livekit = roomError;
    const storageError = await deleteStorage(auth.serverId, leftovers.avatarPaths);
    if (storageError) errors.storage = storageError;

    return CustomResponse.success({ server_id: auth.serverId, errors });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});

/** What the cascade will not clean up, read while the rows still exist. */
async function collectLeftovers(serverId: string) {
  const { data: channels } = await supabase
    .from(DBSchema.channels.tableName)
    .select(DBSchema.channels.id)
    .eq(DBSchema.channels.serverId, serverId)
    .eq(DBSchema.channels.channelType, "voice");
  const { data: users } = await supabase
    .from(DBSchema.users.tableName)
    .select(DBSchema.users.avatarPath)
    .eq(DBSchema.users.serverId, serverId)
    .not(DBSchema.users.avatarPath, "is", null);
  return {
    voiceChannelIds: (channels ?? []).map((c: Record<string, any>) => c[DBSchema.channels.id] as string),
    avatarPaths: (users ?? []).map((u: Record<string, any>) => u[DBSchema.users.avatarPath] as string),
  };
}

/**
 * Drops every voice channel's room, disconnecting whoever is in it.
 *
 * Never throws. A channel with no call has no room, and LiveKit says so with
 * an error that is not worth reporting; anything else is.
 */
async function deleteRooms(serverId: string, channelIds: string[]): Promise<string | null> {
  if (channelIds.length === 0) return null;
  try {
    const roomService = await livekitRoomService(supabase, serverId);
    if (!roomService) return "credentials_missing";
    // Ask which rooms exist before deleting any. Rooms are named by channel
    // id and most channels are text, so deleting by id blind meant a round
    // trip per channel and a "not found" for nearly all of them — a server
    // with two hundred channels paid two hundred of them, in series, while
    // the owner waited on a delete. `listRooms` answers for the whole list at
    // once, and what comes back is exactly what there is to delete.
    const live = await roomService.listRooms(channelIds);
    const failures = (await Promise.all(
      live.map(async (room) => {
        try {
          await roomService.deleteRoom(room.name);
          return null;
        } catch (err) {
          // A call that emptied between the listing and here is already gone.
          return String(err).includes("not found") ? null : `${room.name}: ${err}`;
        }
      }),
    )).filter((f): f is string => f !== null);
    return failures.length === 0 ? null : failures.join("; ");
  } catch (err) {
    return String(err);
  }
}

/** The server's own bucket, whole, and its members' avatars from the shared one. */
async function deleteStorage(serverId: string, avatarPaths: string[]): Promise<string | null> {
  const failures: string[] = [];
  const bucket = `chat-${serverId}`;
  const { error: emptyError } = await supabase.storage.emptyBucket(bucket);
  if (emptyError && !emptyError.message.toLowerCase().includes("not found")) {
    failures.push(`empty ${bucket}: ${emptyError.message}`);
  } else {
    const { error: dropError } = await supabase.storage.deleteBucket(bucket);
    if (dropError && !dropError.message.toLowerCase().includes("not found")) {
      failures.push(`delete ${bucket}: ${dropError.message}`);
    }
  }
  if (avatarPaths.length > 0) {
    const { error } = await supabase.storage.from(AVATARS_BUCKET).remove(avatarPaths);
    if (error) failures.push(`avatars: ${error.message}`);
  }
  return failures.length === 0 ? null : failures.join("; ");
}
