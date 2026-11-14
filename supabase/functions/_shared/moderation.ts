import { TrackSource } from "livekit-server-sdk";
import type { ConnectionKind } from "./livekit.ts";

/**
 * What a moderation flag means in LiveKit terms.
 *
 * These are applied in two places that must not drift: minted into the grant
 * when a member joins (`get_channel_token`) and pushed onto their live
 * connections the moment a moderator acts (`moderate_user`). If the two ever
 * disagreed, a mute would behave differently depending on whether the target
 * happened to already be in the call.
 */

/** A silenced member keeps camera and screen share; only the microphone goes. */
export const MUTED_SOURCES = [
  TrackSource.CAMERA,
  TrackSource.SCREEN_SHARE,
  TrackSource.SCREEN_SHARE_AUDIO,
];

/**
 * Whether the microphone is denied.
 *
 * **A deafened member is muted too.** You cannot hold up your end of a
 * conversation you cannot hear, and it is what every client already draws — so
 * either flag takes the microphone, and only the microphone.
 */
export function micDenied(isMuted: boolean, isDeafened: boolean): boolean {
  return isMuted || isDeafened;
}

/**
 * Publishable sources for an **AccessToken grant**, where `undefined` means
 * "every source".
 */
export function grantSources(
  isMuted: boolean,
  isDeafened: boolean,
): TrackSource[] | undefined {
  return micDenied(isMuted, isDeafened) ? MUTED_SOURCES : undefined;
}

/**
 * Publishable sources for a **live ParticipantPermission update**, where an
 * *empty list* means "every source" — the opposite encoding to the grant's
 * `undefined`. Mixing the two up silently mutes everyone or no one, which is
 * why they are separate functions rather than one shared value.
 */
export function permissionSources(
  isMuted: boolean,
  isDeafened: boolean,
): TrackSource[] {
  return micDenied(isMuted, isDeafened) ? MUTED_SOURCES : [];
}

/**
 * The permission set a live connection of [kind] should hold. Permissions are
 * replaced atomically by `updateParticipant`, so every field has to be stated
 * — omitting one clears it.
 *
 * **Per kind, matching what each was minted with.** This once gave every
 * connection a voice connection's set, so muting someone who was sharing let
 * their share connection subscribe: the share token's "never listens" undone
 * by a moderator's click, with the share hidden from the roster. A watch
 * connection given that set could publish.
 */
export function livePermissionsFor(
  kind: ConnectionKind,
  isMuted: boolean,
  isDeafened: boolean,
  // False for a bot without a `bot_voice_grants` row for this room: a mute
  // must not hand a bot the ears it was never granted (BOTS.md §6b).
  mayListen = true,
  // `mayUseSoundboard` in this room (`_shared/soundboard.ts`): a press is
  // the only data packet a member sends. False unless said, so a caller
  // that forgets takes the soundboard rather than handing it out.
  soundboard = false,
) {
  switch (kind) {
    case "voice":
      return {
        canSubscribe: !isDeafened && mayListen,
        canPublish: true,
        canPublishData: soundboard,
        canPublishSources: permissionSources(isMuted, isDeafened),
        // As minted. LiveKit replaces the whole set on an update, and a right
        // left out is taken away: muted and unmuted, a member could no longer
        // publish being deafened, push-to-talk or what they watch, until
        // they rejoined.
        canUpdateMetadata: true,
      };
    case "share":
      return {
        canSubscribe: false,
        canPublish: true,
        // As minted: a share sends no packets, and one that could would be
        // a second way to press a clip.
        canPublishData: false,
        canPublishSources: permissionSources(isMuted, isDeafened),
        canUpdateMetadata: true,
      };
    case "watch":
      return {
        canSubscribe: !isDeafened && mayListen,
        canPublish: false,
        canPublishData: false,
        canPublishSources: [],
        canUpdateMetadata: false,
        // Visible, as minted (`watchGrant`): a hidden one would listen unseen.
        hidden: false,
      };
  }
}

/**
 * Whether a live connection is held without its microphone: sources that
 * name some but not the microphone. An empty list is every source (see
 * [permissionSources]), so it is not.
 */
export function micHeldBack(sources: TrackSource[] | undefined): boolean {
  return (sources?.length ?? 0) > 0 && !sources!.includes(TrackSource.MICROPHONE);
}

/** The flags as every client reads them off participant metadata. */
export function moderationMetadata(isMuted: boolean, isDeafened: boolean): string {
  return JSON.stringify({ muted: isMuted, deafened: isDeafened });
}
