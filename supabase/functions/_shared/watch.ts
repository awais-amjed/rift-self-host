import { RoomServiceClient, VideoGrant } from "livekit-server-sdk";
import { connectionKind, WATCH_SUFFIX } from "./livekit.ts";

/**
 * The desktop's watch connection: a second connection to a call that only
 * receives, so a stream being watched can be decoded and drawn outside the
 * app's own call connection (the app's `docs/gpu-codecs/STEP3_PLAN.md`).
 *
 * **It is a second connection that listens, so it is never hidden.** A voice
 * connection is in the roster and a share publishes nothing it can hear. A
 * hidden watch connection would be a way to hear a call without being shown
 * in it, which is the hole the share token closed. So it is visible like any
 * other participant, and the app folds it into its owner rather than drawing
 * it twice (`ParticipantIdentity.isWatch`). Four rules keep it tied to a
 * device that is in the call:
 *
 * - it is minted only while the same device's voice connection is in the
 *   room (`admitWatcher`);
 * - one whose voice connection has gone is removed: when LiveKit reports a
 *   voice connection leaving or a watcher joining (`livekit_webhook`), whenever
 *   anyone mints one in that room, and whenever a member's roster is read
 *   (`voice_roster`);
 * - kicks and bans remove it with the rest of the member's connections, since
 *   they match the user id, and moderation sets its permissions as a watcher's
 *   (`livePermissionsFor`);
 * - if every one of those is missed, a region with no webhook set up say, the
 *   watcher is still on everyone's screen as its owner, still in the call.
 */
/**
 * How long a watch token can be used to join. Short, because the presence
 * check happens only when it is minted: a token that outlived its device's
 * voice connection was a way back in. The app asks for a fresh one for every
 * connect, and LiveKit renews the token of a connection that is up.
 */
export const WATCH_TOKEN_TTL = "1m";

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
  const identities = await sweepOrphanedWatchers(service, room);
  return identities?.includes(voiceIdentity) ?? false;
}

/**
 * Remove [room]'s orphaned watchers, answering who was in it, or null when
 * the room did not answer.
 *
 * Decided from the room as it is now, not from whatever event prompted the
 * sweep, so asking twice, late, or with an old event is harmless: a watcher
 * whose voice connection is back is never touched.
 */
export async function sweepOrphanedWatchers(
  service: RoomServiceClient,
  room: string,
): Promise<string[] | null> {
  let identities: string[];
  try {
    identities = (await service.listParticipants(room)).map((p) => p.identity);
  } catch {
    return null;
  }
  await removeWatchers(service, room, orphanedWatchers(identities));
  return identities;
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
 * so it can say nothing in the call; visible, so nobody listens unseen; and
 * never an admin, whatever its owner is.
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
    hidden: false,
    roomAdmin: false,
  };
}
