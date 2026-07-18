import "@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "@supabase/supabase-js";
import DBSchema from "../_shared/schema.ts";
import { corsHeaders } from "../_shared/cors.ts";
import { CustomResponse } from "../_shared/response.ts";
import * as EC from "../_shared/error_codes.ts";
import { authenticateToken, extractBearerToken, isAuthError } from "../_shared/auth.ts";
import { checkChannel, checkEnvelopeFields } from "../_shared/chat.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const MAX_ENTRIES = 500;

/**
 * Store sealed channel-key entries (Design 2 keyring writes): bootstrap of a
 * new key version, or healing missing entries of an existing one.
 *
 * Race arbitration (locked decision): the whole batch is one INSERT with no
 * ON CONFLICT — if any (channel_id, key_version, user_id) already exists the
 * entire statement fails with 23505 and the caller gets `keyring_conflict`:
 * first writer wins, losers refetch and re-wrap the winner's key. A new
 * version may only be `current_version + 1`.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, key_version, entries } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    if (!Number.isInteger(key_version) || key_version < 1) {
      return CustomResponse.error("Invalid key_version", EC.ENVELOPE_INVALID);
    }
    if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_ENTRIES) {
      return CustomResponse.error(
        `entries must be a non-empty array of at most ${MAX_ENTRIES}`,
        EC.MISSING_FIELDS,
      );
    }
    for (const entry of entries) {
      if (typeof entry?.user_id !== "string" || !entry.user_id) {
        return CustomResponse.error("Invalid entry: user_id", EC.ENVELOPE_INVALID);
      }
      const fieldError = checkEnvelopeFields({
        ciphertext: entry.ciphertext,
        nonce: entry.nonce,
      });
      if (fieldError) return fieldError;
      if (
        typeof entry.ephemeral_public_key !== "string" ||
        entry.ephemeral_public_key.length === 0 ||
        entry.ephemeral_public_key.length > 64
      ) {
        return CustomResponse.error("Invalid entry: ephemeral_public_key", EC.ENVELOPE_INVALID);
      }
    }

    // A new version can only be one past the current highest.
    const { data: versionData, error: versionError } = await supabase
      .from(DBSchema.channelKeyring.tableName)
      .select(DBSchema.channelKeyring.keyVersion)
      .eq(DBSchema.channelKeyring.channelId, channel_id)
      .order(DBSchema.channelKeyring.keyVersion, { ascending: false })
      .limit(1);

    if (versionError) {
      return CustomResponse.error("Error reading keyring", EC.DB_ERROR, versionError);
    }
    const currentVersion = versionData && versionData.length > 0
      ? (versionData[0] as Record<string, any>)[DBSchema.channelKeyring.keyVersion] as number
      : 0;
    if (key_version > currentVersion + 1) {
      return CustomResponse.error(
        `key_version ${key_version} skips ahead (current is ${currentVersion})`,
        EC.KEYRING_CONFLICT,
      );
    }

    // Every target user must be a member of this server.
    const userIds = [...new Set(entries.map((e: Record<string, any>) => e.user_id as string))];
    const { data: usersData, error: usersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(DBSchema.users.id)
      .eq(DBSchema.users.serverId, auth.serverId)
      .in(DBSchema.users.id, userIds);

    if (usersError) {
      return CustomResponse.error("Error validating members", EC.DB_ERROR, usersError);
    }
    if ((usersData ?? []).length !== userIds.length) {
      return CustomResponse.error("Unknown user in entries", EC.USER_NOT_FOUND);
    }

    const rows = entries.map((entry: Record<string, any>) => ({
      [DBSchema.channelKeyring.channelId]: channel_id,
      [DBSchema.channelKeyring.keyVersion]: key_version,
      [DBSchema.channelKeyring.userId]: entry.user_id,
      [DBSchema.channelKeyring.wrappedBy]: auth.userId,
      [DBSchema.channelKeyring.ephemeralPublicKey]: entry.ephemeral_public_key,
      [DBSchema.channelKeyring.ciphertext]: entry.ciphertext,
      [DBSchema.channelKeyring.nonce]: entry.nonce,
    }));

    const { error: insertError } = await supabase
      .from(DBSchema.channelKeyring.tableName)
      .insert(rows);

    if (insertError) {
      // 23505 = unique violation → another writer won; caller re-wraps.
      if ((insertError as Record<string, any>).code === "23505") {
        return CustomResponse.error(
          "Keyring entries already exist for this version — refetch and re-wrap",
          EC.KEYRING_CONFLICT,
          insertError,
        );
      }
      return CustomResponse.error("Error storing keyring entries", EC.DB_ERROR, insertError);
    }

    return CustomResponse.success({
      channel_id,
      key_version,
      entries_stored: rows.length,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
