import { TrackSource } from "livekit-server-sdk";

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
 * The permission set a live participant should hold. Permissions are replaced
 * atomically by `updateParticipant`, so every field has to be stated — omitting
 * one clears it.
 */
export function livePermissions(isMuted: boolean, isDeafened: boolean) {
  return {
    canSubscribe: !isDeafened,
    canPublish: true,
    canPublishData: true,
    canPublishSources: permissionSources(isMuted, isDeafened),
  };
}

/** The flags as every client reads them off participant metadata. */
export function moderationMetadata(isMuted: boolean, isDeafened: boolean): string {
  return JSON.stringify({ muted: isMuted, deafened: isDeafened });
}
