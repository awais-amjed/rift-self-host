import { RoomServiceClient, VideoGrant } from "livekit-server-sdk";
import { connectionKind, WATCH_SUFFIX } from "./livekit.ts";

/**
 * The desktop's watch connection: a second connection to a call that only
 * receives, so a stream being watched can be decoded and drawn outside the
 * app's own call connection (the app's `docs/gpu-codecs/STEP3_PLAN.md`).
 *
 * **It is the one connection that can listen without being seen.** A voice
 * connection is in the roster and a share publishes nothing it can hear. A
 * watch connection subscribes and is hidden, because showing it would put
 * everyone watching a stream in the call twice. That is the hole the share
 * token closed, so three rules keep it from opening here:
 *
 * - it is minted only while the same device's voice connection is in the
 *   room (`admitWatcher`), so nobody can listen to a call they are not shown in;
 * - one whose voice connection has gone is removed — whenever anyone mints
 *   one in that room, and whenever a member's roster is read (`voice_roster`);
 * - kicks and bans remove it with the rest of the member's connections, since
 *   they match the user id, and moderation sets its permissions as a watcher's
 *   (`livePermissionsFor`).
 *
 * What is left: between the voice connection going and the next mint or
 * roster read, a watcher can go on receiving for a moment. Accepted by the
 * owner, Nov 2 2026 — it is the member's own device, which a moment earlier
 * was in the call and heard the same.
 */

/** The watch identity for a voice identity. */
export function watchIdentity(voiceIdentity: string): string {
  return `${voiceIdentity}${WATCH_SUFFIX}`;
}

/** Watch connections whose own device's voice connection is not among [identities]. */
export function orphanedWatchers(identities: string[]): string[] {
  const present = new Set(identities);
  return identities.filter((identity) =>
    connectionKind(identity) === "watch" &&
    !present.has(identity.slice(0, -WATCH_SUFFIX.length))
  );
}

/**
 * Whether [voiceIdentity] is in [room] right now, sweeping the room's orphaned
 * watchers on the way.
 *
 * One `listParticipants` answers both. A room that does not answer is a
 * refusal: the check is the reason the token is safe to give.
 */
export async function admitWatcher(
  service: RoomServiceClient,
  room: string,
  voiceIdentity: string,
): Promise<boolean> {
  let identities: string[];
  try {
    identities = (await service.listParticipants(room)).map((p) => p.identity);
  } catch {
    return false;
  }
  await removeWatchers(service, room, orphanedWatchers(identities));
  return identities.includes(voiceIdentity);
}

/** Remove [identities] from [room], each on its own: one already gone is not a failure. */
export async function removeWatchers(
  service: RoomServiceClient,
  room: string,
  identities: string[],
): Promise<void> {
  await Promise.all(
    identities.map((identity) => service.removeParticipant(room, identity).catch(() => {})),
  );
}

/**
 * The grant for a watch connection.
 *
 * Subscribes as its voice connection does; publishes nothing, not even data,
 * so it can say nothing in the call; hidden, so it is not drawn as a second
 * copy of its owner; and never an admin, whatever its owner is.
 */
export function watchGrant(room: string, maySubscribe: boolean): VideoGrant {
  return {
    roomCreate: false,
    roomJoin: true,
    room,
    canPublish: false,
    canPublishData: false,
    canSubscribe: maySubscribe,
    canUpdateOwnMetadata: false,
    hidden: true,
    roomAdmin: false,
  };
}
