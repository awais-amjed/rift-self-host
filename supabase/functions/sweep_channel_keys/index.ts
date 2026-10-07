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

/// How many old-version entries one answer asks the caller to seal. A server
/// that has rotated often and taken on many members since owes a lot of them
/// at once, and the caller seals them all before it posts. The rest are named
/// by `more: true` and come out of the next pass.
const HISTORY_SEALS = 200;

/**
 * Key-distribution sweep (Phase 2, ARCHITECTURE.md §4): one call that lists
 * every channel where the caller can do healing work —
 * - channels whose current key version the caller holds while other eligible
 *   members lack an entry (returns the caller's sealed key + the missing
 *   members' chat public keys),
 * - channels with no key at all (`key_version: 0`) so the caller can
 *   bootstrap v1, and
 * - channels that owe a rotation, so the caller can mint the next version for
 *   the people still entitled to one, and
 * - older versions the caller holds and an eligible member lacks, so somebody
 *   who joined after a rotation can read what was said before it.
 * Clients run this on launch/server-select and when the key-sweep doorbell
 * rings, so a new member gets access as soon as any member is online.
 *
 * **Voice channels are included**, and used not to be — they held no messages,
 * so they held no keys and there was nothing to sweep. Calls are now encrypted
 * with the channel's own key (ARCHITECTURE.md §5), which makes the omission a
 * hole rather than an optimisation: without it a banned member's voice key is
 * never rotated away from them, and a new member is only ever keyed by whoever
 * happens to join a call next.
 *
 * This runs as the service role, so the row-level security policies are not protecting it.
 * Everything it is allowed to say comes from `channel_eligible_members`, which
 * is the same answer the policies give. It exists because four
 * hand-written filters is four places for that answer to drift.
 */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const token = extractBearerToken(req);
    const auth = await authenticateToken(supabase, token);
    if (isAuthError(auth)) return auth;

    // Every channel of this server, of either kind. A voice channel's key is
    // what its calls are encrypted with, and it rotates for the same reasons a
    // text channel's does.
    const { data: channelsData, error: channelsError } = await supabase
      .from(DBSchema.channels.tableName)
      .select(`${DBSchema.channels.id}, rotate_from_key_version`)
      .eq(DBSchema.channels.serverId, auth.serverId);
    if (channelsError) {
      return CustomResponse.error("Error reading channels", EC.DB_ERROR, channelsError);
    }
    const allChannels = (channelsData ?? []) as Record<string, any>[];
    const channelIds = allChannels.map((c) => c[DBSchema.channels.id] as string);
    if (channelIds.length === 0) {
      return CustomResponse.success({ work: [] });
    }
    const rotateMarkOf = (channelId: string) =>
      (allChannels.find((c) => c[DBSchema.channels.id] === channelId)
        ?.rotate_from_key_version ?? null) as number | null;

    // Who may hold a key in each channel, and from which version. One row per
    // (channel, person): a member from v1, a granted bot from its grant.
    const { data: eligibleData, error: eligibleError } = await supabase
      .from("channel_eligible_members")
      .select("channel_id, user_id, chat_public_key, from_key_version")
      .in("channel_id", channelIds);
    if (eligibleError) {
      return CustomResponse.error("Error reading eligibility", EC.DB_ERROR, eligibleError);
    }
    const eligible = (eligibleData ?? []) as Record<string, any>[];

    /// Who a key for [channelId] at [version] may be sealed to.
    ///
    /// The floor has to be applied per channel *and* per version: a grant is
    /// not a property of the bot, it is a property of the pair, and it starts
    /// somewhere.
    const eligibleFor = (channelId: string, version: number) =>
      eligible
        .filter((e) =>
          e.channel_id === channelId && version >= (e.from_key_version as number)
        )
        .map((e) => ({
          user_id: e.user_id as string,
          chat_public_key: e.chat_public_key as string,
        }));

    // A private channel the caller is not in is not the caller's work, and
    // listing it here would tell them it exists.
    const myChannels = channelIds.filter((id) =>
      eligible.some((e) => e.channel_id === id && e.user_id === auth.userId)
    );
    if (myChannels.length === 0) {
      return CustomResponse.success({ work: [] });
    }

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
      .in(DBSchema.channelKeyring.channelId, myChannels);
    if (ringError) {
      return CustomResponse.error("Error reading keyring", EC.DB_ERROR, ringError);
    }
    const ring = (ringData ?? []) as Record<string, any>[];

    const work: Record<string, any>[] = [];
    let historyLeft = HISTORY_SEALS;
    let more = false;
    for (const channelId of myChannels) {
      const channelRing = ring.filter(
        (r) => r[DBSchema.channelKeyring.channelId] === channelId,
      );
      const currentVersion = channelRing.reduce(
        (max, r) => Math.max(max, r[DBSchema.channelKeyring.keyVersion] as number),
        0,
      );

      // Scrollback. Healing below seals only the current version, so before
      // this a member who joined after a rotation (a ban, a bot grant) got the
      // newest key and nothing older: every message from before it stayed
      // locked for them for good, however many members were online who could
      // have opened it. Newest first, since recent history is what gets read.
      //
      // Two floors keep this from undoing what a rotation was for. A granted
      // bot is eligible only from its grant's version (`eligibleFor`), so
      // grants stay forward-only. And nothing at or below
      // `rotate_from_key_version` goes to anyone who lacks it: those versions
      // are what a channel said while it was private, and opening it up is
      // not inviting everyone into that. The mark only ever rises, so the
      // latest one covers every earlier private stretch too.
      const mark = rotateMarkOf(channelId);
      for (let v = currentVersion - 1; v >= 1; v--) {
        if (mark !== null && v <= mark) break;
        const held = channelRing.filter(
          (r) => r[DBSchema.channelKeyring.keyVersion] === v,
        );
        const myOld = held.find(
          (r) => r[DBSchema.channelKeyring.userId] === auth.userId,
        );
        if (!myOld) continue;
        const holders = new Set(
          held.map((r) => r[DBSchema.channelKeyring.userId] as string),
        );
        const lacking = eligibleFor(channelId, v)
          .filter((m) => !holders.has(m.user_id));
        if (lacking.length === 0) continue;
        if (historyLeft === 0) {
          more = true;
          break;
        }
        const batch = lacking.slice(0, historyLeft);
        if (batch.length < lacking.length) more = true;
        historyLeft -= batch.length;
        work.push({
          channel_id: channelId,
          key_version: v,
          rotate: false,
          my_key: {
            ephemeral_public_key: myOld[DBSchema.channelKeyring.ephemeralPublicKey],
            ciphertext: myOld[DBSchema.channelKeyring.ciphertext],
            nonce: myOld[DBSchema.channelKeyring.nonce],
          },
          members_missing: batch,
        });
      }

      if (currentVersion === 0) {
        // No key yet — offer a bootstrap (only meaningful if somebody can hold
        // the result).
        const first = eligibleFor(channelId, 1);
        if (first.length > 0) {
          work.push({
            channel_id: channelId,
            key_version: 0,
            rotate: false,
            my_key: null,
            members_missing: first,
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
      if (!mine) continue;

      const nowEligible = eligibleFor(channelId, currentVersion);
      const nowEligibleIds = new Set(nowEligible.map((m) => m.user_id));
      const missing = nowEligible.filter((m) => !covered.has(m.user_id));

      // Rotation takes precedence over healing, and supersedes it: it seals to
      // everybody eligible, so anyone who was merely missing an entry gets one
      // out of the same pass.
      //
      // Three signals, and all three clear themselves for the same reason — the
      // next version is sealed only to whoever is eligible *then*, so each check
      // comes back false once the rotation lands. Nothing to set, nothing to
      // reset, and an admin who grants and revokes twice in a minute leaves
      // nothing behind to reconcile.
      //
      //   * somebody sealed into the current version who is no longer entitled
      //     to it — a banned member, a member removed from a private channel, a
      //     bot whose grant was revoked. One check, because they are one fact:
      //     the server can stop serving them, but it cannot take back what they
      //     already unwrapped, so everything from now on has to move.
      //
      //   * somebody whose entitlement *begins* above the current version. That
      //     is a grant just made, and the rotation is precisely what makes it
      //     forward-only: without it the bot would be handed a key that opens
      //     everything already said under it.
      //
      //   * a channel that has just been opened up. `rotate_from_key_version`
      //     is set when a private channel goes public, because healing
      //     seals the *current* version — and the current version is the one
      //     the private conversation was written under. Nobody new is sealed
      //     until the sweep is past the mark.
      const sealedButNotEntitled = current.some(
        (r) => !nowEligibleIds.has(r[DBSchema.channelKeyring.userId] as string),
      );
      const entitlementAhead = eligibleFor(channelId, currentVersion + 1).some(
        (m) => !nowEligibleIds.has(m.user_id),
      );
      const openedUp = mark !== null && currentVersion <= mark;

      if (sealedButNotEntitled || entitlementAhead || openedUp) {
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

    return CustomResponse.success({ work, more });
  } catch (err) {
    return CustomResponse.error(`Unexpected error: ${err}`, EC.UNEXPECTED_ERROR, err);
  }
});
