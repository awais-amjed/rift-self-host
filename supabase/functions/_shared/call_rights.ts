import { SupabaseClient } from "@supabase/supabase-js";
import { ParticipantInfo, RoomServiceClient, TrackSource } from "livekit-server-sdk";
import DBSchema from "./schema.ts";
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
 * somebody joins (`livekit_webhook`). It is the only packet a member sends: a
 * move or a rejoin comes from the LiveKit API, which no permission stops.
 */
export interface CallRights {
  speak: boolean;
  soundboard: boolean;
}

/** Neither: what an unreadable answer comes to where failing closed is right. */
export const NO_CALL_RIGHTS: CallRights = { speak: false, soundboard: false };

/** [userId]'s [CallRights] in [channelId]'s call; null if either was unreadable. */
export async function channelRights(
  supabase: SupabaseClient,
  userId: string,
  channelId: string,
): Promise<CallRights | null> {
  const [speak, soundboard] = await Promise.all(
    ["SPEAK", "USE_SOUNDBOARD"].map((name) =>
      supabase.rpc("user_has_channel_permission", {
        p_user: userId, p_channel: channelId, p_name: name,
      })
    ),
  );
  if (speak.error || soundboard.error) return null;
  const maySpeak = speak.data === true;
  return { speak: maySpeak, soundboard: maySpeak && soundboard.data === true };
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
 * With [leaveUnreadable], a connection whose rights could not be read is
 * left as it is rather than held back: the join check (`livekit_webhook`)
 * comes moments after a token was minted from the same rules, and a database
 * hiccup must not take the microphone from everybody joining during it.
 * Without it, unreadable is no `SPEAK`, failing closed as `get_channel_token`
 * does.
 */
export async function reconcileConnections(
  supabase: SupabaseClient,
  service: RoomServiceClient,
  channelId: string,
  connections: ParticipantInfo[],
  { leaveUnreadable = false } = {},
): Promise<number> {
  const userIds = [...new Set(connections.map((p) => p.identity.split("~")[0]))];
  if (userIds.length === 0) return 0;

  const [{ data: users, error: usersError }, { data: grants, error: grantsError }, rights] =
    await Promise.all([
      supabase
        .from(DBSchema.users.tableName)
        .select(
          `${DBSchema.users.id}, ${DBSchema.users.isMuted}, ${DBSchema.users.isDeafened}, ` +
            `${DBSchema.users.isBot}`,
        )
        .in(DBSchema.users.id, userIds),
      supabase
        .from("bot_voice_grants")
        .select("bot_id")
        .eq("channel_id", channelId)
        .in("bot_id", userIds),
      Promise.all(userIds.map(async (id) =>
        [id, await channelRights(supabase, id, channelId)] as const
      )),
    ]);
  // Nobody's flags known, nothing to decide. Without the grants every bot
  // would read as deaf, which is closed, so only the join check stops there.
  if (usersError || (grantsError && leaveUnreadable)) return 0;

  const byId = new Map(
    (users ?? []).map((u) => [(u as Record<string, any>)[DBSchema.users.id] as string, u as Record<string, any>]),
  );
  const botListens = new Set((grants ?? []).map((g) => (g as Record<string, any>).bot_id as string));
  const rightsOf = new Map(rights);

  let updated = 0;
  await Promise.all(connections.map(async (participant) => {
    const userId = participant.identity.split("~")[0];
    const user = byId.get(userId);
    if (!user) return;
    const read = rightsOf.get(userId) ?? null;
    if (read === null && leaveUnreadable) return;
    const { speak, soundboard } = read ?? NO_CALL_RIGHTS;

    const kind = connectionKind(participant.identity);
    const isMuted = user[DBSchema.users.isMuted] === true;
    const isDeafened = user[DBSchema.users.isDeafened] === true;
    const isBot = user[DBSchema.users.isBot] === true;
    const quiet = isMuted || !speak;
    const permission = livePermissionsFor(
      kind,
      quiet,
      isDeafened,
      !isBot || botListens.has(userId),
      soundboard,
    );
    // A watch connection is minted without the flags; the other two carry
    // them, and a token kept from before a mute would still say unmuted.
    const metadata = kind === "watch" ? undefined : moderationMetadata(isMuted, isDeafened);
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

    if (kind !== "watch" && micDenied(quiet, isDeafened)) {
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
