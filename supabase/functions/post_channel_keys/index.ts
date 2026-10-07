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
 * Race arbitration (locked decision): minting a version (`mint: true`) is one
 * INSERT with no ON CONFLICT — if any (channel_id, key_version, user_id)
 * already exists the entire statement fails with 23505 and the caller gets
 * `keyring_conflict`: first writer wins, losers refetch and re-wrap the
 * winner's key. A new version may only be `current_version + 1`. Healing an
 * existing version (`mint: false`) skips entries that are already there.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { channel_id, key_version, entries, mint, link } = await req.json();
    const token = extractBearerToken(req);

    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    const channel = await checkChannel(supabase, channel_id, auth.serverId);
    if (channel instanceof Response) return channel;

    // The same gate `get_channel_key` puts in front of the read, in front of
    // the write — which is the half that was missing.
    //
    // `checkChannel` only asks whether the channel is on this server. That is
    // the whole of what a channel id proves, and this function runs on the
    // service role, where the policy that would have asked the rest
    // (`channel_keyring_insert`, via `app.can_see_channel`) does not apply. So
    // a member who was never in a private channel could name it, seal version
    // n+1 to the people who are, and — because the insert below has no
    // ON CONFLICT and nobody holds DELETE on the keyring — leave them a
    // current version they cannot open and cannot replace.
    //
    // Answered as "not found" rather than "forbidden", like every other
    // refusal about a room you cannot see. The version arithmetic below is
    // past this on purpose: `key_version N skips ahead (current is M)` names
    // M, and M is a fact about a private channel's key.
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
    // A client says which it is doing (012). Minting is the race: the version
    // must be exactly the next one, and the first batch to land wins it. A
    // later batch of the same version, from the same minter or anybody else
    // holding it, is healing, which only ever seals a key the sender unwrapped
    // from its own entry. Those skip entries somebody else wrote first, so two
    // members healing the same channel at once both get their work in, rather
    // than one losing a whole batch to a single overlap.
    //
    // A client that sends neither is older than this and keeps the old
    // all-or-nothing insert.
    if (mint === true && key_version !== currentVersion + 1) {
      return CustomResponse.error(
        `key_version ${key_version} was minted already (current is ${currentVersion})`,
        EC.KEYRING_CONFLICT,
      );
    }
    if (mint === false && key_version > currentVersion) {
      return CustomResponse.error(
        `key_version ${key_version} does not exist yet (current is ${currentVersion})`,
        EC.KEYRING_CONFLICT,
      );
    }

    // Every target user must be a member of this server.
    const userIds = [...new Set(entries.map((e: Record<string, any>) => e.user_id as string))];
    const { data: usersData, error: usersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(`${DBSchema.users.id}, ${DBSchema.users.isBot}`)
      .eq(DBSchema.users.serverId, auth.serverId)
      .in(DBSchema.users.id, userIds);

    if (usersError) {
      return CustomResponse.error("Error validating members", EC.DB_ERROR, usersError);
    }
    if ((usersData ?? []).length !== userIds.length) {
      return CustomResponse.error("Unknown user in entries", EC.USER_NOT_FOUND);
    }

    // A bot holds a channel key only where an admin granted one, and only from
    // the version the grant names (BOTS.md §6). `refuse_ineligible_keyring`
    // says the same thing on the row, but a trigger raises for the whole
    // statement — so one ineligible bot in a batch would fail the wrap for
    // every real member beside it, and the client would see a database error
    // rather than the reason. Refusing here names it, and does so before
    // anything is written.
    //
    // Checking the grant rather than the bot flag is the whole of it. A
    // blanket refusal here outlived the rule it came from, and what it broke
    // was not only the grant: the sweep seals the next version to *everyone*
    // eligible, so one granted bot in the batch refused the rotation itself —
    // and a channel with a grant on it could then never rotate for any other
    // reason either, a banned member's included.
    const bots = ((usersData ?? []) as Record<string, any>[])
      .filter((u) => u[DBSchema.users.isBot] === true)
      .map((u) => u[DBSchema.users.id] as string);
    if (bots.length > 0) {
      const { data: grantData, error: grantError } = await supabase
        .from("bot_channel_keys")
        .select("bot_id, from_key_version")
        .eq("channel_id", channel_id)
        .in("bot_id", bots);
      if (grantError) {
        return CustomResponse.error("Error reading bot grants", EC.DB_ERROR, grantError);
      }
      const grantedFrom = new Map(
        ((grantData ?? []) as Record<string, any>[])
          .map((g) => [g.bot_id as string, g.from_key_version as number]),
      );
      const refused = bots.filter((id) => {
        const from = grantedFrom.get(id);
        return from === undefined || key_version < from;
      });
      if (refused.length > 0) {
        return CustomResponse.error(
          "Channel keys cannot be wrapped for a bot without a grant to this " +
            "channel at this key version",
          EC.PERMISSION_DENIED,
        );
      }
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

    const { error: insertError } = mint === false
      ? await supabase
        .from(DBSchema.channelKeyring.tableName)
        .upsert(rows, {
          onConflict: `${DBSchema.channelKeyring.channelId},` +
            `${DBSchema.channelKeyring.keyVersion},${DBSchema.channelKeyring.userId}`,
          ignoreDuplicates: true,
        })
      : await supabase
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

    // The previous version sealed under this one (013), stored only once the
    // version is won: a link written before the race was settled could seal
    // the old key under the loser's. Best-effort — a rotation with no link
    // still works, its members just keep a row for the version before.
    // `store_channel_key_link` refuses one across an opening or a bot grant.
    let linkStored = false;
    if (
      mint === true && key_version >= 2 &&
      typeof link?.ciphertext === "string" && typeof link?.nonce === "string"
    ) {
      const { data: stored, error: linkError } = await supabase.rpc(
        "store_channel_key_link",
        {
          p_channel: channel_id,
          p_version: key_version,
          p_by: auth.userId,
          p_ciphertext: link.ciphertext,
          p_nonce: link.nonce,
        },
      );
      linkStored = !linkError && stored === true;
    }

    return CustomResponse.success({
      channel_id,
      key_version,
      entries_stored: rows.length,
      link_stored: linkStored,
    });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
