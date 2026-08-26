import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkChannel } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/**
 * Keyring read for one channel (ARCHITECTURE.md §4, Design 2). Returns:
 * - `my_keys`: every keyring entry sealed to the caller (all versions —
 *   full-scrollback decision), opaque to the server.
 * - `current_version`: the highest key version in this channel (0 = no key
 *   yet — the caller should bootstrap v1).
 * - `members_missing`: members with a published chat key but no entry for
 *   `current_version`, with their X25519 public keys — any member's client
 *   can heal them by wrapping and posting entries (this is the
 *   pending-key-request sweep primitive).
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    // All keyring rows for this channel (id + version + user for the roster
    // math; sealed fields only kept for the caller's own rows).
    const { data: ringData, error: ringError } = await supabase
      .from(DBSchema.channelKeyring.tableName)
      .select(
        `${DBSchema.channelKeyring.keyVersion},` +
        ` ${DBSchema.channelKeyring.userId},` +
        ` ${DBSchema.channelKeyring.ephemeralPublicKey},` +
        ` ${DBSchema.channelKeyring.ciphertext},` +
        ` ${DBSchema.channelKeyring.nonce}`,
      )
      .eq(DBSchema.channelKeyring.channelId, channel_id);

    if (ringError) {
      return CustomResponse.error("Error reading keyring", EC.DB_ERROR, ringError);
    }

    const ring = (ringData ?? []) as Record<string, any>[];
    const currentVersion = ring.reduce(
      (max, row) => Math.max(max, row[DBSchema.channelKeyring.keyVersion] as number),
      0,
    );

    const myKeys = ring
      .filter((row) => row[DBSchema.channelKeyring.userId] === auth.userId)
      .map((row) => ({
        key_version: row[DBSchema.channelKeyring.keyVersion],
        ephemeral_public_key: row[DBSchema.channelKeyring.ephemeralPublicKey],
        ciphertext: row[DBSchema.channelKeyring.ciphertext],
        nonce: row[DBSchema.channelKeyring.nonce],
      }))
      .sort((a, b) => a.key_version - b.key_version);

    // Members with a published chat key but no entry at the current version.
    // When currentVersion is 0 this is every keyed member — the bootstrap set.
    const { data: membersData, error: membersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.chatPublicKey}`)
      .eq(DBSchema.users.serverId, auth.serverId)
      .eq(DBSchema.users.isBanned, false)
      // Bots are never "missing" a key — they are not supposed to have one
      // (BOTS.md §2). Without this the first member to open the channel would
      // wrap it for them as a courtesy, having been asked to do nothing.
      // `channel_keyring` refuses the row anyway (migration 014); this keeps
      // clients from trying and reporting a failure they cannot act on.
      .eq(DBSchema.users.isBot, false)
      .not(DBSchema.users.chatPublicKey, "is", null);

    if (membersError) {
      return CustomResponse.error("Error reading members", EC.DB_ERROR, membersError);
    }

    const covered = new Set(
      ring
        .filter((row) => row[DBSchema.channelKeyring.keyVersion] === currentVersion)
        .map((row) => row[DBSchema.channelKeyring.userId] as string),
    );

    const membersMissing = ((membersData ?? []) as Record<string, any>[])
      .filter((m) => !covered.has(m[DBSchema.users.id] as string))
      .map((m) => ({
        user_id: m[DBSchema.users.id],
        chat_public_key: m[DBSchema.users.chatPublicKey],
      }));

    return CustomResponse.success({
      current_version: currentVersion,
      my_keys: myKeys,
      members_missing: membersMissing,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
