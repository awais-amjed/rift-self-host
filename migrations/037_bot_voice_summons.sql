-- ============================================================
-- Rift self-hosted server — 037: summoning a bot into a call
-- ============================================================
-- Asking the music bot to come and play. It is the thing people most want a bot
-- for, and until now it did not work at all in a private voice channel and
-- worked only by accident in a public one.
--
-- Two walls stood in a private channel, both keyed on `channel_members`, which
-- `set_channel_members` refuses to seat a bot into:
--
--   * `channel_visible_to` — no token, so `get_channel_token` answers
--     `CHANNEL_NOT_FOUND`;
--   * `bot_voice_key_candidates` — no member's client seals it a media key, and
--     calls are end-to-end encrypted, so there is nothing for it to speak with.
--
-- A summon is the third door, and it is deliberately the smallest one: it lets
-- a bot into **one voice channel**, to **publish**, until somebody dismisses it.
--
-- ---------- why this can be a default permission ----------
--
-- `SUMMON_BOTS` is on `@everyone` (036), which sounds alarming for private
-- channels until you see what a summoned bot gets. Its token is minted with
-- `canSubscribe: false` unless an admin separately granted listening, and its
-- media key is `HMAC(channelKey, 'voicebot:v1:<botId>')` — derived *from* the
-- channel key rather than being it, so members can hear the bot and the bot
-- cannot invert the HMAC to hear them. A summon adds a speaker to the room. It
-- does not add a listener, and it cannot be made into one from here.
--
-- It also does not make the bot a member: `app.sees_channel` is untouched, so a
-- summoned bot cannot list the channel, read its roster, read its messages, or
-- post in it. Only `channel_joinable_by` knows about summons, and only
-- `get_channel_token` asks that.
--
-- ---------- and why the candidates view got narrower ----------
--
-- It used to list every bot on the server for every public voice channel, so
-- members' clients sealed a media key for bots that would never join. Now a
-- summon is what puts a bot on the list. That is less work for every client and
-- one less thing sitting in the database for no reason — and it is what makes
-- dismissing meaningful, because dropping the summon drops the key with it.

-- ============================================================
-- 1. The summon
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_summons (
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id      UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- Who asked. A bot in a call that nobody remembers inviting is the thing
  -- this column answers, and it is the same reason `bot_channel_keys` keeps
  -- `granted_by`.
  summoned_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  summoned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

CREATE INDEX IF NOT EXISTS bot_voice_summons_bot ON bot_voice_summons (bot_id);

COMMENT ON TABLE bot_voice_summons IS
  'Bots asked into a voice channel, until dismissed (migration 037). Permission '
  'to publish there and nothing else: it does not make the bot a member, and it '
  'does not let it hear — that is bot_voice_grants and MANAGE_BOTS.';

CREATE OR REPLACE FUNCTION app.bot_summoned_to(p_channel UUID, p_bot UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_voice_summons s
                  WHERE s.channel_id = p_channel AND s.bot_id = p_bot)
$$;

-- ============================================================
-- 2. Who may join a voice channel
-- ============================================================
-- `channel_visible_to` answers "may this person see this channel", which is the
-- question for a person and the wrong one for a summoned bot: it is in the room
-- without being of it. Separating them keeps the summon from leaking anywhere
-- else — every other caller still asks `sees_channel` and still gets no.

CREATE OR REPLACE FUNCTION channel_joinable_by(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.sees_channel(p_channel, p_user)
      OR (EXISTS (SELECT 1 FROM users u WHERE u.id = p_user
                    AND u.is_bot AND NOT u.is_banned)
          AND app.bot_summoned_to(p_channel, p_user))
$$;

REVOKE ALL ON FUNCTION channel_joinable_by(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION channel_joinable_by(UUID, UUID) TO service_role;

-- ============================================================
-- 3. Asking, and asking it to leave
-- ============================================================

CREATE OR REPLACE FUNCTION summon_bot_to_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type TEXT;
BEGIN
  IF NOT app.has_perm('SUMMON_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- The caller's own visibility, not the bot's — a summon is somebody in the
  -- room asking, and the whole point is that the bot cannot see it yet.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT channel_type INTO v_type FROM channels WHERE id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Dismissing takes no permission beyond being able to see the room. Anybody in
-- a call may ask the music bot to stop, and needing the person who summoned it
-- — who may have left — is how a bot ends up playing to an empty room.
CREATE OR REPLACE FUNCTION dismiss_bot_from_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_channel) AND p_bot IS DISTINCT FROM auth.uid() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_summons
   WHERE channel_id = p_channel AND bot_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION summon_bot_to_voice(UUID, UUID)    FROM PUBLIC;
REVOKE ALL ON FUNCTION dismiss_bot_from_voice(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION summon_bot_to_voice(UUID, UUID)    TO authenticated;
GRANT EXECUTE ON FUNCTION dismiss_bot_from_voice(UUID, UUID) TO authenticated;

-- ============================================================
-- 4. Dismissing takes the key with it
-- ============================================================
-- Same shape as `drop_bot_voice_keys_on_grant_change` (032), and for the same
-- reason: a key sealed under one decision must not outlive it. Without this a
-- dismissed bot keeps a usable media key and only the token stands between it
-- and the room.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_summon_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

REVOKE ALL ON FUNCTION drop_bot_voice_keys_on_summon_change() FROM PUBLIC;

DROP TRIGGER IF EXISTS bot_voice_summons_reset_keys ON bot_voice_summons;
CREATE TRIGGER bot_voice_summons_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_summons
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_summon_change();

-- ============================================================
-- 5. What a client seals, and for whom
-- ============================================================
-- A summon is now what puts a bot on the list, in a private channel and a
-- public one alike. Members' clients stop sealing media keys for bots that
-- will never join, and dropping a summon drops the key with it.

CREATE OR REPLACE VIEW bot_voice_key_candidates
  WITH (security_invoker = false) AS
  SELECT c.id  AS channel_id,
         u.id  AS bot_id,
         u.chat_public_key,
         EXISTS (SELECT 1 FROM bot_voice_grants g
                  WHERE g.channel_id = c.id AND g.bot_id = u.id) AS may_listen
    FROM channels c
    JOIN bot_voice_summons s ON s.channel_id = c.id
    JOIN users u ON u.id = s.bot_id
   WHERE c.channel_type = 'voice'
     AND u.is_bot
     AND NOT u.is_banned
     AND u.chat_public_key IS NOT NULL;

-- ============================================================
-- 6. Security
-- ============================================================

ALTER TABLE bot_voice_summons ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_summons FROM anon, authenticated;
GRANT SELECT ON bot_voice_summons TO authenticated;

-- Readable by the room, so a member can see what has been called in, and by the
-- bot itself, which is how it learns where it has been asked to go. `bot_id =
-- auth.uid()` rather than a join through `can_see_channel`: a summoned bot is
-- not in the channel, and that is the point of the summon.
DROP POLICY IF EXISTS bot_voice_summons_select ON bot_voice_summons;
CREATE POLICY bot_voice_summons_select ON bot_voice_summons
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());

-- No write grant at all: summoning moves through the functions above, so a row
-- cannot appear without the permission check that justifies it.
