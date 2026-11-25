import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { livekitRoomServices } from "../_shared/livekit.ts";

/**
 * Delete a server: everything it holds, and everything holding it up.
 *
 * The `delete_server` RPC, run with the caller's own JWT so the database is
 * what decides, refuses anyone but the owner and marks the server: from then
 * on nobody is a member of it. Its rows go afterwards, in pieces, by
 * `purge_deleted_servers` — every minute, and once from here straight after
 * the mark, which is all a small server needs. Deleting them in the owner's
 * request ran into its statement timeout past some 600 members, and the
 * server could not be deleted at all. What the database cannot reach is done
 * here with the service role, after the RPC has said yes:
 *
 *   * the LiveKit room of every voice channel, which disconnects whoever is
 *     still in one — the same reason `delete_channel` is an edge function;
 *   * the `chat-<serverId>` attachment bucket, which `storage.protect_delete()`
 *     keeps out of reach of every database role;
 *   * each member's avatar, in the shared `avatars` bucket;
 *   * the server's icons, its folder of the shared `servers` bucket.
 *
 * Every one of those, and the first purge, is best-effort and reported back,
 * not swallowed: a LiveKit that cannot be reached must not leave the owner
 * with a server that will not go away, and a storage object that outlives
 * its server is a leak, not a breach — the bucket's policies were keyed on a
 * membership that no longer exists.
 */
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const AVATARS_BUCKET = "avatars";
const ICONS_BUCKET = "servers";

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
    const roomError = await deleteRooms(leftovers.services, leftovers.voiceChannelIds);
    if (roomError) errors.livekit = roomError;
    const storageError = await deleteStorage(auth.serverId, leftovers.avatarPaths);
    if (storageError) errors.storage = storageError;
    const { pending, error: purgeError } = await purgeNow(auth.serverId);
    if (purgeError) errors.purge = purgeError;

    return CustomResponse.success({ server_id: auth.serverId, pending, errors });
  } catch (err) {
    return CustomResponse.error("Unexpected error", EC.UNEXPECTED_ERROR, err);
  }
});

/**
 * What the cascade will not clean up, read while the rows still exist.
 *
 * The LiveKit admin clients too: they are built from `server_secrets` and the
 * nodes' keys, which the cascade deletes. Read afterwards, there were none,
 * so no room was ever deleted and every call on the server went on.
 */
async function collectLeftovers(serverId: string) {
  const { data: channels } = await supabase
    .from(DBSchema.channels.tableName)
    .select(DBSchema.channels.id)
    .eq(DBSchema.channels.serverId, serverId)
    .eq(DBSchema.channels.channelType, "voice");
  // Paged: a read stops at the API's row cap, and every avatar past it would
  // stay in storage for good.
  const avatarPaths: string[] = [];
  for (let from = 0;; from += AVATAR_PAGE) {
    const { data: users, error } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.avatarPath)
      .eq(DBSchema.users.serverId, serverId)
      .not(DBSchema.users.avatarPath, "is", null)
      .order(DBSchema.users.id)
      .range(from, from + AVATAR_PAGE - 1);
    if (error || !users) break;
    avatarPaths.push(
      ...users.map((u: Record<string, any>) => u[DBSchema.users.avatarPath] as string),
    );
    if (users.length < AVATAR_PAGE) break;
  }
  return {
    voiceChannelIds: (channels ?? []).map((c: Record<string, any>) => c[DBSchema.channels.id] as string),
    avatarPaths,
    services: await livekitRoomServices(supabase, serverId),
  };
}

const AVATAR_PAGE = 1000;

/**
 * Drops every voice channel's room, disconnecting whoever is in it.
 *
 * Never throws. A channel with no call has no room, and LiveKit says so with
 * an error that is not worth reporting; anything else is.
 */
async function deleteRooms(
  services: Awaited<ReturnType<typeof livekitRoomServices>>,
  channelIds: string[],
): Promise<string | null> {
  if (channelIds.length === 0) return null;
  try {
    // Every node, because the server's calls may be spread across them and a
    // deleted server must not leave one running anywhere.
    if (services.length === 0) return "credentials_missing";
    // Ask which rooms exist before deleting any. Rooms are named by channel
    // id and most channels are text, so deleting by id blind meant a round
    // trip per channel and a "not found" for nearly all of them — a server
    // with two hundred channels paid two hundred of them, in series, while
    // the owner waited on a delete. `listRooms` answers for the whole list at
    // once, and what comes back is exactly what there is to delete.
    const live = (await Promise.all(
      services.map(async ({ service }) => {
        try {
          return (await service.listRooms(channelIds)).map((room) => ({ room, service }));
        } catch {
          return [];
        }
      }),
    )).flat();
    const failures = (await Promise.all(
      live.map(async ({ room, service }) => {
        try {
          await service.deleteRoom(room.name);
          return null;
        } catch (err) {
          // A call that emptied between the listing and here is already gone.
          if (String(err).includes("not found")) return null;
          console.error("[delete_server] room", room.name, err);
          return room.name;
        }
      }),
    )).filter((f): f is string => f !== null);
    return failures.length === 0 ? null : `livekit_unreachable: ${failures.join(", ")}`;
  } catch (err) {
    console.error("[delete_server] rooms", err);
    return "livekit_unreachable";
  }
}

/**
 * The server's own bucket, whole, and from the shared ones its members'
 * avatars and its icons.
 */
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
  const { data: icons, error: listError } = await supabase.storage.from(ICONS_BUCKET).list(serverId);
  if (listError) {
    failures.push(`icons: ${listError.message}`);
  } else if (icons && icons.length > 0) {
    const { error } = await supabase.storage
      .from(ICONS_BUCKET)
      .remove(icons.map((icon: { name: string }) => `${serverId}/${icon.name}`));
    if (error) failures.push(`icons: ${error.message}`);
  }
  return failures.length === 0 ? null : failures.join("; ");
}

/**
 * The purge's first pass, so a small server's rows are gone before this
 * answers. Bounded well inside the API's statement timeout; whatever is left
 * the minute's job finishes. `pending` is whether any of this server's rows
 * are still waiting for it.
 */
async function purgeNow(serverId: string): Promise<{ pending: boolean; error?: string }> {
  const { error } = await supabase.rpc("purge_deleted_servers", { p_seconds: PURGE_SECONDS });
  const { data: left, error: readError } = await supabase
    .from(DBSchema.servers.tableName)
    .select(DBSchema.servers.id)
    .eq(DBSchema.servers.id, serverId)
    .maybeSingle();
  return {
    pending: readError !== null || left !== null,
    error: error ? error.message : undefined,
  };
}

const PURGE_SECONDS = 4;
