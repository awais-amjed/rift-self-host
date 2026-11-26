import { SupabaseClient } from "@supabase/supabase-js";
import { ParticipantInfo, RoomServiceClient, TrackSource } from "livekit-server-sdk";
import { connectionKind } from "./livekit.ts";
import {
  holdsAlready,
  livePermissionsFor,
  micDenied,
  moderationMetadata,
} from "./moderation.ts";

/**
 * What a voice channel lets someone do in its call beyond being there: speak,
 * and press a soundboard clip. Both are the channel's bits
 * (`user_has_channel_permission`), so a channel can override a role's.
 *
 * A clip is sound in the call, so it needs `SPEAK` as well as
 * `USE_SOUNDBOARD`: Listen-only takes it too (the app's
 * `SoundboardCubit.mayPlay`).
 *
 * A press is a LiveKit data packet that every listener plays for itself, so
 * no server sees it. What stops one is the connection's `canPublishData`,
 * minted from this (`get_channel_token`) and pushed when a channel's
 * permissions change (`set_channel_override`), a moderator acts
 * (`moderate_user`), a bot's ears are granted (`set_bot_voice_listen`) or
 * somebody joins (`livekit_webhook`). A press is the only packet a member
 * sends: the "clipped the last minute" notice (`rift.clip`), a move and a
 * rejoin come from the LiveKit API (`note_clip`, `move_user`, `move_call`),
 * which no permission stops and no member can fake. A DM call's token asks
 * the same two bits of the server (`get_dm_call_token`).
 */
export interface CallRights {
  speak: boolean;
  soundboard: boolean;
}

/** Neither: what an unreadable answer comes to where failing closed is right. */
export const NO_CALL_RIGHTS: CallRights = { speak: false, soundboard: false };

/**
 * What a call holds one person to, as `call_rights_for` (065) answers it: the
 * door (`channel_joinable_by`), the channel's call bits, the moderation flags
 * and a bot's ears. `soundboard` already needs `speak`.
 */
export interface CallRightsRow extends CallRights {
  joinable: boolean;
  connect: boolean;
  screenShare: boolean;
  isMuted: boolean;
  isDeafened: boolean;
  isBot: boolean;
  botListens: boolean;
}

/**
 * [userIds]' [CallRightsRow]s in [channelId]'s call, in one database call,
 * by id; a member with no row is missing. Null when it was unreadable.
 *
 * Each of these was its own questions: the door, then `SPEAK` and
 * `USE_SOUNDBOARD` per person, each working that person's bits out again, then
 * the flags and the grants. A call of forty was over a hundred round trips.
 */
export async function readCallRights(
  supabase: SupabaseClient,
  channelId: string,
  userIds: string[],
): Promise<Map<string, CallRightsRow> | null> {
  const ids = [...new Set(userIds)].filter((id) => id.length > 0);
  if (ids.length === 0) return new Map();
  const { data, error } = await supabase.rpc("call_rights_for", {
    p_channel: channelId,
    p_users: ids,
  });
  if (error) return null;
  const rights = new Map<string, CallRightsRow>();
  for (const row of (data ?? []) as Record<string, any>[]) {
    rights.set(row.user_id as string, {
      joinable: row.joinable === true,
      connect: row.connect === true,
      screenShare: row.screen_share === true,
      speak: row.speak === true,
      soundboard: row.soundboard === true,
      isMuted: row.is_muted === true,
      isDeafened: row.is_deafened === true,
      isBot: row.is_bot === true,
      botListens: row.bot_listens === true,
    });
  }
  return rights;
}

/** [userId]'s [CallRights] in [channelId]'s call; null if unreadable. */
export async function channelRights(
  supabase: SupabaseClient,
  userId: string,
  channelId: string,
): Promise<CallRights | null> {
  const rights = await readCallRights(supabase, channelId, [userId]);
  if (rights === null) return null;
  const row = rights.get(userId);
  return row ? { speak: row.speak, soundboard: row.soundboard } : NO_CALL_RIGHTS;
}

/**
 * Make each of [connections] in [channelId]'s call hold what the server says
 * now: the microphone by `SPEAK` and the moderation flags, the soundboard by
 * [channelRights], the ears by deafening and a bot's grant, and the flags
 * every client draws in the metadata. Answers how many were pushed.
 *
 * A connection already right is left alone, since `updateParticipant`
 * replaces the whole permission set and there is no reason to touch one that
 * did not move.
 *
 * [rights] is what a caller already read for these people
 * ([readCallRights]); without it they are read here. Unreadable changes
 * nothing: neither anybody's flags nor their bits are known, and a database
 * hiccup must not take the microphone from a whole call.
 */
export async function reconcileConnections(
  supabase: SupabaseClient,
  service: RoomServiceClient,
  channelId: string,
  connections: ParticipantInfo[],
  rights?: Map<string, CallRightsRow> | null,
): Promise<number> {
  const userIds = [...new Set(connections.map((p) => p.identity.split("~")[0]))];
  if (userIds.length === 0) return 0;

  const known = rights ?? await readCallRights(supabase, channelId, userIds);
  if (known === null) return 0;

  let updated = 0;
  await Promise.all(connections.map(async (participant) => {
    const userId = participant.identity.split("~")[0];
    const user = known.get(userId);
    if (!user) return;

    const kind = connectionKind(participant.identity);
    const quiet = user.isMuted || !user.speak;
    const permission = livePermissionsFor(
      kind,
      quiet,
      user.isDeafened,
      !user.isBot || user.botListens,
      user.soundboard,
    );
    // A watch connection is minted without the flags; the other two carry
    // them, and a token kept from before a mute would still say unmuted.
    const metadata = kind === "watch" ? undefined : moderationMetadata(user.isMuted, user.isDeafened);
    if (
      holdsAlready(kind, participant.permission, permission) &&
      (metadata === undefined || participant.metadata === metadata)
    ) {
      return;
    }

    // The permission before the mute, as in `moderate_user`: the first stops
    // the next publish, the second the audio already flowing.
    await service.updateParticipant(
      channelId,
      participant.identity,
      metadata === undefined ? { permission } : { metadata, permission },
    );
    updated++;

    if (kind !== "watch" && micDenied(quiet, user.isDeafened)) {
      await Promise.all(
        (participant.tracks ?? [])
          .filter((track) => track.source === TrackSource.MICROPHONE && !track.muted)
          .map((track) =>
            service.mutePublishedTrack(channelId, participant.identity, track.sid, true)
          ),
      );
    }
  }));
  return updated;
}

/**
 * The connections in [channelId]'s call of anybody who may no longer be
 * there, by the question `get_channel_token` asks at the door
 * (`channel_joinable_by`). A summoned bot is in the call without a seat, and
 * stays. Unreadable is left alone: a database hiccup must not throw a whole
 * call out. [rights] as for [reconcileConnections]; a connection whose
 * member row has gone is outside.
 */
export async function connectionsOutside(
  supabase: SupabaseClient,
  channelId: string,
  connections: ParticipantInfo[],
  rights?: Map<string, CallRightsRow> | null,
): Promise<ParticipantInfo[]> {
  const userIds = [...new Set(connections.map((p) => p.identity.split("~")[0]))];
  if (userIds.length === 0) return [];
  const known = rights ?? await readCallRights(supabase, channelId, userIds);
  if (known === null) return [];
  return connections.filter((p) => known.get(p.identity.split("~")[0])?.joinable !== true);
}
