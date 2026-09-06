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
 * - `bots_missing` (voice channels only): bots that may speak here and have no
 *   key for `current_version`, and whether each may also hear. A member's
 *   client seals them the same way it heals a member — a bot's media key is
 *   derived from the channel key, so only somebody holding that can produce
 *   one (migration 032).
 * - `my_voice_key`: for a bot caller, its own sealed media key. Bots have no
 *   `channel_keyring` rows and never will; this is the one thing they get.
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
      // 037: a summoned bot is in the room without being of it.
      //
      // It cannot *see* this channel — `channel_visible_to` stays the whole
      // truth for every other caller — but it does have to open the media key a
      // member sealed for it, or it joins the call and publishes frames nobody
      // can decrypt. `get_channel_token` already admits it on exactly this
      // test, and the SDK asks for the key one call *earlier* (`voice.ts`), so
      // without this the flow 037 was written to allow fails before reaching
      // the function that allows it.
      //
      // The answer is the narrowest thing that works: its own sealed key and
      // nothing else. No keyring, no roster, no version count — a summoned bot
      // learns nothing here that was not already sealed to it by hand.
      const { data: joinable, error: joinableError } = await supabase.rpc(
        "channel_joinable_by",
        { p_channel: channel_id, p_user: auth.userId },
      );
      if (joinableError) {
        return CustomResponse.error("Error reading channel access", EC.DB_ERROR, joinableError);
      }
      if (joinable !== true) {
        return CustomResponse.error("Channel not found", EC.CHANNEL_NOT_FOUND);
      }

      // Its newest sealed row, rather than the one at the channel's current
      // version: the version on the row is what the bot maps onto LiveKit's key
      // ring, and reading the keyring to learn the channel's version would be
      // telling it something this branch exists to withhold.
      const { data: sealed, error: sealedError } = await supabase
        .from("bot_voice_keys")
        .select("key_version, is_channel_key, ephemeral_public_key, ciphertext, nonce")
        .eq("channel_id", channel_id)
        .eq("bot_id", auth.userId)
        .order("key_version", { ascending: false })
        .limit(1);
      if (sealedError) {
        return CustomResponse.error("Error reading voice key", EC.DB_ERROR, sealedError);
      }

      return CustomResponse.success({
        current_version: 0,
        my_keys: [],
        members_missing: [],
        bots_missing: [],
        my_voice_key: (sealed ?? [])[0] ?? null,
      });
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

    // Voice: who still needs a media key, and — for a bot asking — its own.
    // Text channels skip all of it; nothing publishes media into one.
    let botsMissing: Record<string, unknown>[] = [];
    let myVoiceKey: Record<string, unknown> | null = null;

    const { data: channelRow } = await supabase
      .from(DBSchema.channels.tableName)
      .select(DBSchema.channels.channelType)
      .eq(DBSchema.channels.id, channel_id)
      .single();
    const isVoice =
      (channelRow as Record<string, any> | null)?.[DBSchema.channels.channelType] ===
        "voice";

    if (isVoice && currentVersion > 0) {
      const { data: sealed } = await supabase
        .from("bot_voice_keys")
        .select("bot_id, is_channel_key, ephemeral_public_key, ciphertext, nonce")
        .eq("channel_id", channel_id)
        .eq("key_version", currentVersion);
      const sealedRows = (sealed ?? []) as Record<string, any>[];

      const mine = sealedRows.find((r) => r.bot_id === auth.userId);
      if (mine) {
        myVoiceKey = {
          key_version: currentVersion,
          is_channel_key: mine.is_channel_key,
          ephemeral_public_key: mine.ephemeral_public_key,
          ciphertext: mine.ciphertext,
          nonce: mine.nonce,
        };
      }

      const { data: candidates } = await supabase
        .from("bot_voice_key_candidates")
        .select("bot_id, chat_public_key, may_listen")
        .eq("channel_id", channel_id);

      // A row whose `is_channel_key` disagrees with the grant is as good as
      // missing: the bot would be encrypting with a key nobody is listening
      // for. The grant trigger drops those, and this is the belt to its braces.
      const held = new Map(
        sealedRows.map((r) => [r.bot_id as string, r.is_channel_key === true]),
      );
      botsMissing = ((candidates ?? []) as Record<string, any>[])
        .filter((b) => held.get(b.bot_id as string) !== (b.may_listen === true))
        .map((b) => ({
          bot_id: b.bot_id,
          chat_public_key: b.chat_public_key,
          may_listen: b.may_listen === true,
        }));
    }

    return CustomResponse.success({
      current_version: currentVersion,
      my_keys: myKeys,
      members_missing: membersMissing,
      bots_missing: botsMissing,
      my_voice_key: myVoiceKey,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
