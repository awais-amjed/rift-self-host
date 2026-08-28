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

    // 020: a private channel is not the caller's unless they are in it. Answered
    // as "not found" rather than "forbidden" — a room you cannot see should not
    // confirm that it exists.
    const { data: visible, error: visibleError } = await supabase.rpc(
      "channel_visible_to",
      { p_channel: channel_id, p_user: auth.userId },
    );
    if (visibleError) {
      return CustomResponse.error("Error reading channel access", EC.DB_ERROR, visibleError);
    }
    if (visible !== true) {
      return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
    }

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

    // Who may hold this channel's key, and from which version. One view rather
    // than a members query plus a bot-grant query plus the rule that joins
    // them: 020 added a third input (private-channel membership), and three
    // filters spread across two edge functions is three places to forget one.
    const { data: eligibleData, error: eligibleError } = await supabase
      .from("channel_eligible_members")
      .select("user_id, chat_public_key, from_key_version")
      .eq("channel_id", channel_id);
    if (eligibleError) {
      return CustomResponse.error("Error reading eligibility", EC.DB_ERROR, eligibleError);
    }

    const covered = new Set(
      ring
        .filter((row) => row[DBSchema.channelKeyring.keyVersion] === currentVersion)
        .map((row) => row[DBSchema.channelKeyring.userId] as string),
    );

    // When currentVersion is 0 this is every eligible member — the bootstrap
    // set — which is why the floor is compared against at least 1.
    const sealingVersion = Math.max(currentVersion, 1);
    const membersMissing = ((eligibleData ?? []) as Record<string, any>[])
      .filter((m) => !covered.has(m.user_id as string))
      .filter((m) => sealingVersion >= (m.from_key_version as number))
      .map((m) => ({
        user_id: m.user_id,
        chat_public_key: m.chat_public_key,
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
