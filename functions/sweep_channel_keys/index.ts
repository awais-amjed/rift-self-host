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
 *   members' chat public keys),
 * - channels with no key at all (`key_version: 0`) so the caller can
 *   bootstrap v1, and
 * - channels whose current key was sealed to somebody since banned
 *   (`rotate: true`), so the caller can mint the next version for the people
 *   still here.
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

    // Everyone on the server, banned included: the banned are not people to
    // seal a key to, but they are exactly who makes a rotation due, so they
    // have to be visible here rather than filtered away by the query.
    const { data: usersData, error: membersError } = await supabase
      .from(DBSchema.users.tableName)
      .select(
        `${DBSchema.users.id}, ${DBSchema.users.chatPublicKey},` +
        ` ${DBSchema.users.isBanned}, ${DBSchema.users.isBot}`,
      )
      .eq(DBSchema.users.serverId, auth.serverId)
      // See get_channel_key: a bot is not a member awaiting a key, and a sweep
      // that offered one as work would hand every client an insert the
      // database is going to refuse.
      .eq(DBSchema.users.isBot, false)
      .not(DBSchema.users.chatPublicKey, "is", null);
    if (membersError) {
      return CustomResponse.error("Error reading members", EC.DB_ERROR, membersError);
    }
    const allUsers = (usersData ?? []) as Record<string, any>[];
    const members = allUsers
      .filter((m) => m[DBSchema.users.isBanned] !== true)
      .map((m) => ({
        user_id: m[DBSchema.users.id] as string,
        chat_public_key: m[DBSchema.users.chatPublicKey] as string,
      }));
    const bannedIds = new Set(
      allUsers
        .filter((m) => m[DBSchema.users.isBanned] === true)
        .map((m) => m[DBSchema.users.id] as string),
    );
    const botIds = new Set(
      allUsers
        .filter((m) => m[DBSchema.users.isBot] === true)
        .map((m) => m[DBSchema.users.id] as string),
    );

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

    // Who may hold a key in each channel, and from which version (migration
    // 017). A bot is keyed only where somebody granted it, and only forward of
    // that grant — which is also what makes the two rotation signals below
    // computable without a flag anybody has to remember to clear.
    const { data: grantData, error: grantError } = await supabase
      .from("bot_channel_keys")
      .select("channel_id, bot_id, from_key_version")
      .in("channel_id", channelIds);
    if (grantError) {
      return CustomResponse.error("Error reading bot grants", EC.DB_ERROR, grantError);
    }
    const grants = (grantData ?? []) as Record<string, any>[];
    const grantFor = (channelId: string, botId: string) =>
      grants.find(
        (g) => g.channel_id === channelId && g.bot_id === botId,
      ) as { from_key_version: number } | undefined;

    /// Who a key for [channelId] at [version] may be sealed to: every member,
    /// plus the bots granted this channel from at or below that version.
    ///
    /// The bots have to be added *per channel and per version*, which is why
    /// this cannot just widen the `members` query — a grant is not a property
    /// of the bot, it is a property of the pair, and it starts somewhere.
    const eligibleFor = (channelId: string, version: number) => [
      ...members,
      ...allUsers
        .filter((m) => {
          if (m[DBSchema.users.isBot] !== true) return false;
          if (m[DBSchema.users.isBanned] === true) return false;
          const grant = grantFor(channelId, m[DBSchema.users.id] as string);
          return grant !== undefined && version >= grant.from_key_version;
        })
        .map((m) => ({
          user_id: m[DBSchema.users.id] as string,
          chat_public_key: m[DBSchema.users.chatPublicKey] as string,
        })),
    ];

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
            rotate: false,
            my_key: null,
            members_missing: eligibleFor(channelId, 1),
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
      const missing = eligibleFor(channelId, currentVersion).filter(
        (m) => !covered.has(m.user_id),
      );

      if (!mine) continue;

      // Rotation takes precedence over healing. A ban leaves the banned member
      // holding the current key — the server can stop serving them, but it
      // cannot take back what they already unwrapped — so everything sent
      // under that key from now on has to move to a new one.
      //
      // Being sealed into the current version is itself the signal, and it
      // clears itself: the next version is sealed only to people still here,
      // so the same check comes back false once the rotation lands. No flag to
      // set, and nothing to reset if an unban follows.
      //
      // The rotation supersedes healing rather than following it: it seals to
      // every eligible member, so anyone who was missing an entry gets one out
      // of the same pass.
      // Three signals, all self-clearing for the same reason: the next version
      // is sealed only to whoever is eligible *then*, so each check comes back
      // false once the rotation lands.
      //
      //   * a banned member still sealed into the current version (the
      //     original);
      //   * a bot still sealed into it whose grant has been revoked — the same
      //     shape, for the same reason;
      //   * a bot whose grant begins *above* the current version. That is a
      //     grant just made, and the rotation is precisely what makes it
      //     forward-only: without it the bot would be handed a key that opens
      //     everything already said under it.
      const revokedBotSealed = current.some((r) => {
        const id = r[DBSchema.channelKeyring.userId] as string;
        return botIds.has(id) && !grantFor(channelId, id);
      });
      const grantAwaitingRotation = grants.some(
        (g) =>
          g.channel_id === channelId &&
          (g.from_key_version as number) > currentVersion,
      );
      const rotationDue =
        current.some(
          (r) => bannedIds.has(r[DBSchema.channelKeyring.userId] as string),
        ) ||
        revokedBotSealed ||
        grantAwaitingRotation;
      if (rotationDue) {
        work.push({
          channel_id: channelId,
          key_version: currentVersion,
          rotate: true,
          // The next key is generated, not unwrapped, so there is nothing to
          // hand back. Only a member who holds the current one is offered the
          // job, so whoever rotates can still read what came before.
          my_key: null,
          // The version being sealed is the *next* one, which is what makes a
          // just-granted bot eligible for it and a just-revoked one not.
          members_missing: eligibleFor(channelId, currentVersion + 1),
        });
        continue;
      }

      if (missing.length > 0) {
        work.push({
          channel_id: channelId,
          key_version: currentVersion,
          rotate: false,
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
