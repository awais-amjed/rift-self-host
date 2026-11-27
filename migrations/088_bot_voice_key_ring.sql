-- ============================================================
-- Rift self-hosted server — 088: a bot hears that its media key was sealed
-- ============================================================
-- Found in the live test of Nov 27 2026: a bot playing into a call went
-- silent the moment the channel's key rotated, and stayed silent until it
-- left the call and was summoned again.
--
-- A rotation moves the members' apps to the new key within a second: they
-- hear the server's `sweep` ring, read the new version, and seal every bot in
-- the call its media key under it (`bot_voice_keys`). The bot was never told.
-- It holds a socket only on its own topic, `user:<bot id>`, and reads its
-- media key once, when it joins. So it went on encrypting under the old key,
-- which the members had already replaced in the slot they read bots from.
--
--   * A row sealed for a bot now rings the bot, `voice_key` on its own topic,
--     with the channel and the version. A nudge, as everything on that topic
--     is: the key is not in it, and the bot reads its row through
--     `my_channel_key` as it does when it joins, under the same rules.
--   * Nothing new can be written. Who may seal a bot a row is still
--     `bot_voice_keys_insert` (061): a member holding the channel's newest
--     version, at that version, once a version (the primary key). So a bot is
--     rung at most once for each version of each channel it is in.
--
-- The SDKs that listen for it are rift-bot-sdk-rust and rift-bot-sdk-node;
-- a bot on an older SDK ignores the ring and behaves as before.

CREATE OR REPLACE FUNCTION app.announce_bot_voice_key() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  PERFORM realtime.send(
    jsonb_build_object('channel_id', NEW.channel_id,
                       'key_version', NEW.key_version),
    'voice_key', 'user:' || NEW.bot_id, true);
  RETURN NULL;
END $$;

COMMENT ON FUNCTION app.announce_bot_voice_key() IS
  'Rings a bot on its own topic when a member seals it a media key, so a bot '
  'already in the call takes the new key (088).';

DROP TRIGGER IF EXISTS bot_voice_keys_announce ON bot_voice_keys;
CREATE TRIGGER bot_voice_keys_announce
  AFTER INSERT ON bot_voice_keys
  FOR EACH ROW EXECUTE FUNCTION app.announce_bot_voice_key();

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.announce_bot_voice_key() FROM PUBLIC, anon, authenticated;
