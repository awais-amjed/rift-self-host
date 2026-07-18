import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Key-distribution sweep (Phase 2, ARCHITECTURE.md §4): one call that lists
 * every text channel where the caller can do healing work —
 * - channels whose current key version the caller holds while other keyed
 *   members lack an entry (returns the caller's sealed key + the missing
 *   members' chat public keys), and
 * - channels with no key at all (`key_version: 0`) so the caller can
 *   bootstrap v1.
 * Clients run this on launch/server-select and when the key-sweep doorbell
 * rings, so a new member gets access as soon as any member is online.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Text channels of this server.
    const { data: channelsData, error: channelsError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.id)
      .eq(DBSchema.channels.serverId, auth.serverId)
      .eq(DBSchema.channels.channelType, "text");
    if (channelsError) {
      return CustomResponse.error("Error reading channels", EC.DB_ERROR, channelsError);
    }
    const channelIds = ((channelsData ?? []) as Record<string, any>[])
      .map((c) => c[DBSchema.channels.id] as string);
    if (channelIds.length === 0) {
      return CustomResponse.success({ work: [] });
    }

    // All keyed members of the server.
    const { data: membersData, error: membersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.chatPublicKey}`)
      .eq(DBSchema.users.serverId, auth.serverId)
      .eq(DBSchema.users.isBanned, false)
      .not(DBSchema.users.chatPublicKey, "is", null);
    if (membersError) {
      return CustomResponse.error("Error reading members", EC.DB_ERROR, membersError);
    }
    const members = ((membersData ?? []) as Record<string, any>[]).map((m) => ({
      user_id: m[DBSchema.users.id] as string,
      chat_public_key: m[DBSchema.users.chatPublicKey] as string,
    }));

    // Whole keyring for those channels in one query.
    const { data: ringData, error: ringError } = await supabase
      .from(DBSchema.channelKeyring.tableName)
      .select(
        `${DBSchema.channelKeyring.channelId},` +
        ` ${DBSchema.channelKeyring.keyVersion},` +
        ` ${DBSchema.channelKeyring.userId},` +
        ` ${DBSchema.channelKeyring.ephemeralPublicKey},` +
        ` ${DBSchema.channelKeyring.ciphertext},` +
        ` ${DBSchema.channelKeyring.nonce}`,
      )
      .in(DBSchema.channelKeyring.channelId, channelIds);
    if (ringError) {
      return CustomResponse.error("Error reading keyring", EC.DB_ERROR, ringError);
    }
    const ring = (ringData ?? []) as Record<string, any>[];

    const work: Record<string, any>[] = [];
    for (const channelId of channelIds) {
      const channelRing = ring.filter(
        (r) => r[DBSchema.channelKeyring.channelId] === channelId,
      );
      const currentVersion = channelRing.reduce(
        (max, r) => Math.max(max, r[DBSchema.channelKeyring.keyVersion] as number),
        0,
      );

      if (currentVersion === 0) {
        // No key yet — offer a bootstrap (only meaningful if members exist).
        if (members.length > 0) {
          work.push({
            channel_id: channelId,
            key_version: 0,
            my_key: null,
            members_missing: members,
          });
        }
        continue;
      }

      const current = channelRing.filter(
        (r) => r[DBSchema.channelKeyring.keyVersion] === currentVersion,
      );
      const covered = new Set(
        current.map((r) => r[DBSchema.channelKeyring.userId] as string),
      );
      const mine = current.find(
        (r) => r[DBSchema.channelKeyring.userId] === auth.userId,
      );
      const missing = members.filter((m) => !covered.has(m.user_id));

      if (mine && missing.length > 0) {
        work.push({
          channel_id: channelId,
          key_version: currentVersion,
          my_key: {
            ephemeral_public_key: mine[DBSchema.channelKeyring.ephemeralPublicKey],
            ciphertext: mine[DBSchema.channelKeyring.ciphertext],
            nonce: mine[DBSchema.channelKeyring.nonce],
          },
          members_missing: missing,
        });
      }
    }

    return CustomResponse.success({ work });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
