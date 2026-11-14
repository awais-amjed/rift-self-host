import { SupabaseClient } from "@supabase/supabase-js";

/**
 * Whether [userId] may fire a soundboard clip in [channelId]'s call: the
 * channel's `USE_SOUNDBOARD` and `SPEAK`, since a clip is sound in the call
 * and Listen-only takes it too (the app's `SoundboardCubit.mayPlay`).
 *
 * A press is a LiveKit data packet that every listener plays for itself, so
 * no server sees it. What stops one is the connection's `canPublishData`,
 * minted from this (`get_channel_token`) and pushed when a channel's
 * permissions change (`set_channel_override`), a moderator acts
 * (`moderate_user`) or a bot's ears are granted (`set_bot_voice_listen`). It
 * is the only packet a member sends: a move or a rejoin comes from the
 * LiveKit API, which no permission stops.
 *
 * Unreadable is not allowed, failing closed as `SPEAK` does.
 */
export async function mayUseSoundboard(
  supabase: SupabaseClient,
  userId: string,
  channelId: string,
): Promise<boolean> {
  const [{ data: soundboard }, { data: speak }] = await Promise.all(
    ["USE_SOUNDBOARD", "SPEAK"].map((name) =>
      supabase.rpc("user_has_channel_permission", {
        p_user: userId, p_channel: channelId, p_name: name,
      })
    ),
  );
  return soundboard === true && speak === true;
}
