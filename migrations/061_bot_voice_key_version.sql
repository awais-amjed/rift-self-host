-- ============================================================
-- Rift self-hosted server — 061: a bot's voice key is sealed at the room's
-- version, by somebody who holds it
-- ============================================================
-- Found in the review of call counts and direct writes, Nov 26 2026.
--
-- Members write `bot_voice_keys` directly, behind `bot_voice_keys_insert`,
-- which asked that the writer could see the voice channel, was no bot, and
-- claimed the channel key only where a listening grant exists. It asked
-- nothing about `key_version`. A bot reads back its newest row
-- (`get_channel_key`) and speaks with whatever it opens, so any member who
-- could see a voice channel could seal a bot a row far ahead of the room,
-- with anything in it, and nobody in the call could hear that bot again until
-- the room's key passed that number.
--
-- The keyring had the same gap and 043 closed it in `post_channel_keys`. This
-- is the same rule for the bot's row: it is sealed at the version the room is
-- on, and only by a member who holds that version, the one thing a bot's key
-- can be derived from. A member holding the key could still seal the bot
-- nonsense at that version, as they could leak the key itself; no database
-- can tell, and it is not what this defends against.
--
-- The app seals at the version it just read and drops a refusal quietly, so
-- a rotation landing in between costs a bot that seal, and the next member to
-- open the call seals it again.

-- True when `p_version` is the newest version of the channel's key and the
-- caller holds it. Definer, since a member reads only their own keyring rows
-- and the newest version may be on somebody else's.
CREATE OR REPLACE FUNCTION app.holds_room_key(p_channel UUID, p_version INTEGER)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM channel_keyring k
                  WHERE k.channel_id = p_channel
                    AND k.key_version = p_version
                    AND k.user_id = auth.uid())
     AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                      WHERE k.channel_id = p_channel
                        AND k.key_version > p_version)
$$;

COMMENT ON FUNCTION app.holds_room_key(UUID, INTEGER) IS
  'For bot_voice_keys_insert: the version is the channel''s newest and the '
  'caller holds it.';

DROP POLICY IF EXISTS bot_voice_keys_insert ON bot_voice_keys;
CREATE POLICY bot_voice_keys_insert ON bot_voice_keys
  FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.may_write_bot_voice_key(channel_id, bot_id, is_channel_key)
    AND app.holds_room_key(channel_id, key_version)
  );

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.holds_room_key(UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.holds_room_key(UUID, INTEGER) TO authenticated;
