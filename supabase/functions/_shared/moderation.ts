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
 * What a voice or share connection may publish: the camera always, the
 * microphone unless it is denied, and the screen and its sound only with the
 * channel's `SCREEN_SHARE`. Phones and browsers share on the voice connection
 * itself, so a token minted for "every source" was a screen share for anybody
 * the channel refused one (security re-review, Nov 26).
 *
 * **Always a list that names each source.** A grant reads a missing list as
 * every source and a live update reads an empty one so; this is never either,
 * so the two encodings cannot be mixed up. A silenced member keeps the camera
 * and, where they may share, the screen and its sound.
 */
export function publishSources(
  isMuted: boolean,
  isDeafened: boolean,
  screenShare: boolean,
): TrackSource[] {
  return [
    ...(micDenied(isMuted, isDeafened) ? [] : [TrackSource.MICROPHONE]),
    TrackSource.CAMERA,
    ...(screenShare ? [TrackSource.SCREEN_SHARE, TrackSource.SCREEN_SHARE_AUDIO] : []),
  ];
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
  // `channelRights` in this room (`_shared/call_rights.ts`): a press is
  // the only data packet a member sends. False unless said, so a caller
  // that forgets takes the soundboard rather than handing it out.
  soundboard = false,
  // The channel's `SCREEN_SHARE` (`_shared/call_rights.ts`). False unless
  // said, as the soundboard is: a caller that forgets takes the screen.
  screenShare = false,
) {
  switch (kind) {
    case "voice":
      return {
        canSubscribe: !isDeafened && mayListen,
        canPublish: true,
        canPublishData: soundboard,
        canPublishSources: publishSources(isMuted, isDeafened, screenShare),
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
        canPublishSources: publishSources(isMuted, isDeafened, screenShare),
        canUpdateMetadata: true,
      };
    case "watch":
      return {
        canSubscribe: !isDeafened && mayListen,
        canPublish: false,
        canPublishData: false,
        canPublishSources: [] as TrackSource[],
        canUpdateMetadata: false,
        // Visible, as minted (`watchGrant`): a hidden one would listen unseen.
        hidden: false,
      };
  }
}

/** [sources] as a set, an empty or missing list being every source. */
function sourceSet(sources: TrackSource[] | undefined): Set<TrackSource> {
  return new Set(
    (sources?.length ?? 0) > 0
      ? sources
      : [
        TrackSource.MICROPHONE,
        TrackSource.CAMERA,
        TrackSource.SCREEN_SHARE,
        TrackSource.SCREEN_SHARE_AUDIO,
      ],
  );
}

/**
 * Whether a live connection of [kind] already holds [wanted] in everything a
 * push moves: its ears, its packets and what it may publish. A watch
 * connection publishes nothing, so its sources are not asked.
 */
export function holdsAlready(
  kind: ConnectionKind,
  held:
    | { canSubscribe?: boolean; canPublishData?: boolean; canPublishSources?: TrackSource[] }
    | undefined,
  wanted: ReturnType<typeof livePermissionsFor>,
): boolean {
  return (held?.canSubscribe ?? false) === wanted.canSubscribe &&
    (held?.canPublishData ?? false) === wanted.canPublishData &&
    (kind === "watch" || sameSources(held?.canPublishSources, wanted.canPublishSources));
}

function sameSources(a: TrackSource[] | undefined, b: TrackSource[] | undefined): boolean {
  const x = sourceSet(a);
  const y = sourceSet(b);
  return x.size === y.size && [...x].every((source) => y.has(source));
}

/** The flags as every client reads them off participant metadata. */
export function moderationMetadata(isMuted: boolean, isDeafened: boolean): string {
  return JSON.stringify({ muted: isMuted, deafened: isDeafened });
}
