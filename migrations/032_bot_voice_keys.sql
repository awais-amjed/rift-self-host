-- ============================================================
-- Rift self-hosted server — 032: the key a bot speaks with
-- ============================================================
-- Voice is end-to-end encrypted from 031 onward, and that broke the one thing
-- BOTS.md §6b had just bought: a bot that publishes into a call but cannot hear
-- it. Encrypting is what makes a bot audible, holding the key is what makes it
-- a listener, and with one key per room those are the same act — §2's "write but
-- not read is not expressible with a key", arriving in voice.
--
-- ---------- two directions, two keys ----------
--
-- The room runs in LiveKit's per-participant key mode, so participants need not
-- share one key. Members use the channel key. A bot uses
--
--     botKey = HMAC-SHA256(channelKey, 'voicebot:v1:<botId>')
--
-- Every member holds `channelKey`, so every member derives `botKey` and hears
-- the bot. The bot is handed only `botKey`, and HMAC does not run backwards, so
-- it cannot reach `channelKey` and cannot decrypt one member's audio. Two bots
-- in one call cannot decrypt each other either — the bot id is in the context.
--
-- ---------- and the listening grant is a key grant now ----------
--
-- 031 made "let this bot hear" a flag on a LiveKit token, and said it was
-- revocable because a permission is not arithmetic. Encryption changes that: a
-- bot that may hear needs `channelKey` itself, and a key that has been handed
-- over cannot be taken back. So a granted bot is sealed the channel key here,
-- `is_channel_key` records which of the two it holds, and revoking now means
-- what it means in §6 — rotate forward, and it keeps what it already heard.
--
-- Worth saying plainly rather than leaving 031's sentence standing.

CREATE TABLE IF NOT EXISTS bot_voice_keys (
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id               UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL,
  -- false: the derived publish key. true: the channel key itself, which only a
  -- bot with a listening grant may be given.
  is_channel_key       BOOLEAN     NOT NULL DEFAULT false,
  wrapped_by           UUID        REFERENCES users(id) ON DELETE SET NULL,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id, key_version)
);

COMMENT ON TABLE bot_voice_keys IS
  'The key a bot encrypts its own media with in one voice channel, sealed to '
  'its chat identity by a member. Derived from the channel key unless the bot '
  'holds a listening grant, in which case it is the channel key.';

CREATE INDEX IF NOT EXISTS bot_voice_keys_bot_idx ON bot_voice_keys (bot_id);

ALTER TABLE bot_voice_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_keys FROM anon, authenticated;
GRANT SELECT, INSERT ON bot_voice_keys TO authenticated;

-- ============================================================
-- 1. Who may write one
-- ============================================================
-- Only somebody who holds the channel key can produce either value, so this is
-- the same shape as healing: any member of the room does the work, and the
-- server checks nothing about the bytes because it cannot read them.
--
-- **A bot may not write here.** It has no channel key to derive from, so a row
-- from a bot is either nonsense or a bot handing another bot something it was
-- not given — and `refuse_bot_keyring` already established that the answer to
-- "should a bot be able to write key material" is no.
--
-- What the server *can* check is the flag: `is_channel_key` is only true where
-- a listening grant exists. A member could still seal the channel key and
-- label it false, and no database can catch that — a member holding the key
-- can leak it anywhere, which is true of every channel and is not what this
-- table defends against. What it defends against is the grant meaning one thing
-- in the UI and another in the room.

CREATE OR REPLACE FUNCTION app.may_write_bot_voice_key(
  p_channel UUID,
  p_bot     UUID,
  p_channel_key BOOLEAN
) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT NOT app.is_bot()
     AND app.can_see_channel(p_channel)
     AND EXISTS (SELECT 1 FROM channels c
                  WHERE c.id = p_channel AND c.channel_type = 'voice')
     AND EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id())
     AND (NOT p_channel_key
          OR EXISTS (SELECT 1 FROM bot_voice_grants g
                      WHERE g.channel_id = p_channel AND g.bot_id = p_bot))
$$;

DROP POLICY IF EXISTS bot_voice_keys_insert ON bot_voice_keys;
CREATE POLICY bot_voice_keys_insert ON bot_voice_keys
  FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.may_write_bot_voice_key(channel_id, bot_id, is_channel_key)
  );

-- ============================================================
-- 2. Who may read one
-- ============================================================
-- The bot, because it is the point. And any member who can see the channel,
-- because they are the ones who notice a bot has no key yet and seal one — the
-- same healing loop the text keyring uses, and it needs to see what is already
-- there or every client re-seals every version on every open.
--
-- The sealed bytes are readable by members and that is harmless: a member seals
-- them and already holds everything they were derived from.

DROP POLICY IF EXISTS bot_voice_keys_select ON bot_voice_keys;
CREATE POLICY bot_voice_keys_select ON bot_voice_keys
  FOR SELECT TO authenticated
  USING (bot_id = auth.uid() OR app.can_see_channel(channel_id));

-- ============================================================
-- 3. A grant that changes takes the row with it
-- ============================================================
-- Granting hearing to a bot that already holds a publish key has to replace
-- that row, or the bot keeps encrypting with a key nobody looks for and stays
-- inaudible. Revoking has the same problem in reverse — and worse, leaving the
-- channel key sealed to a bot whose grant is gone is the grant not actually
-- being revoked.
--
-- Dropping the rows is enough: the next member into the call finds the bot
-- missing a key for the current version and seals the right one.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_grant_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS bot_voice_grants_reset_keys ON bot_voice_grants;
CREATE TRIGGER bot_voice_grants_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_grants
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_grant_change();

-- ============================================================
-- 4. What a client needs to seal
-- ============================================================
-- Bots eligible to speak in a voice channel that have no key for the version
-- in force. Service-role only, like `channel_eligible_members` (021): it is the
-- answer the policies give, computed once, so four hand-written filters do not
-- become four places to forget one.
--
-- Every bot on the server that can see the channel is listed, grant or no
-- grant. Speaking is not the part that needs allowing — a bot with no grant
-- gets the derived key and still cannot hear a word.

CREATE OR REPLACE VIEW bot_voice_key_candidates
  WITH (security_invoker = false) AS
  SELECT c.id  AS channel_id,
         u.id  AS bot_id,
         u.chat_public_key,
         EXISTS (SELECT 1 FROM bot_voice_grants g
                  WHERE g.channel_id = c.id AND g.bot_id = u.id) AS may_listen
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
   WHERE c.channel_type = 'voice'
     AND u.is_bot
     AND NOT u.is_banned
     AND u.chat_public_key IS NOT NULL
     AND (NOT c.is_private
          OR EXISTS (SELECT 1 FROM channel_members m
                      WHERE m.channel_id = c.id AND m.user_id = u.id));

COMMENT ON VIEW bot_voice_key_candidates IS
  'Bots that may speak in each voice channel, and whether they may also hear '
  'it. Read by get_channel_key so a member''s client can seal what is missing.';

REVOKE ALL ON bot_voice_key_candidates FROM anon, authenticated;
