-- ============================================================
-- Rift self-hosted server — 031: what a bot may hear in a call
-- ============================================================
-- BOTS.md's rule is "a bot hears what you tell it, not what you say", and
-- until this migration voice was the one place it was simply false.
--
-- `get_channel_token` never asked whether the caller was a bot. `@everyone`
-- carries CONNECT and SPEAK, a bot holds `@everyone` like anybody else, and the
-- token was minted with `canSubscribe` true. So any bot invited to a server
-- could sit in a call and receive every participant's audio, indefinitely, with
-- nothing said in any channel and nothing shown to anyone in the room.
--
-- Nobody built that on purpose. It is what happens when a rule is enforced in
-- the text path and the voice path is written by asking "what does a member
-- need", which is the same shape as the bug this whole document exists to
-- avoid.
--
-- ---------- publishing is not hearing ----------
--
-- The bot people actually ask for first is a music bot, and a music bot only
-- ever *publishes*. It needs no grant, and after this migration it gets none:
-- its token can play audio into the room and receives nothing back.
--
-- That covers the common case outright, which is what makes the strict default
-- affordable. Transcription, an AI that answers out loud, a recorder — those
-- genuinely need to hear, and they need an explicit grant.
--
-- ---------- unlike a key, this one can be taken back ----------
--
-- §6 grants a bot a channel *key*, and the awkward half of that section is that
-- a key is arithmetic: revoking rotates forward and the bot keeps everything it
-- already unwrapped. Nothing can be done about it.
--
-- Voice is not encrypted end to end — media is DTLS-SRTP to the server's own
-- LiveKit, which the operator runs (ARCHITECTURE.md §5). Subscription is
-- therefore a *permission*, not a key, and permissions really do come back:
-- revoking pushes `canSubscribe: false` onto the bot's live connection and the
-- audio stops mid-call. So this grant is honestly reversible in a way §6's is
-- not, and it is worth saying so rather than describing them as the same thing.
--
-- ---------- no server-wide form ----------
--
-- §6 has a bulk grant because thirty channels one at a time produces a button
-- somebody else builds without thinking. That argument does not carry here:
-- there is no MEE6 of voice, listening to a room full of people is a larger
-- decision than reading a text channel, and "every call on this server, plus
-- the ones made later" is not a thing anybody should be able to click once.
-- Per channel is the only form.

-- ============================================================
-- 1. The grant
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_grants (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

COMMENT ON TABLE bot_voice_grants IS
  'Bots whose LiveKit token may subscribe in this voice channel. Absent a row '
  'a bot publishes and hears nothing. Read by get_channel_token when it mints '
  'the grant, and by every client to draw the recording light.';

CREATE INDEX IF NOT EXISTS bot_voice_grants_bot_idx ON bot_voice_grants (bot_id);

ALTER TABLE bot_voice_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_grants FROM anon, authenticated;

-- Readable by anyone who can see the channel, which is §6's fourth rule
-- arriving in voice: the admin grants, and everybody who ever speaks in that
-- room pays for it. They are not the same people, so the notice cannot live in
-- the dialog where the decision was made.
--
-- `can_see_channel` rather than `server_id`: a private voice channel's
-- membership is not public, and neither is what is listening to it.
GRANT SELECT ON bot_voice_grants TO authenticated;

DROP POLICY IF EXISTS bot_voice_grants_select ON bot_voice_grants;
CREATE POLICY bot_voice_grants_select ON bot_voice_grants
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

-- ============================================================
-- 2. Granting and taking back
-- ============================================================
-- Both return a reason rather than raising, matching grant_bot_channel_key —
-- the caller is a dialog, and "forbidden" and "no such bot" are things it draws
-- differently rather than an exception it reports.
--
-- There is no system message on either. A voice channel holds no messages: it
-- carries the columns and ignores them (ARCHITECTURE.md §3), so a line in the
-- scrollback would be a line nothing renders. The notice is the standing
-- marker in the channel and the bot's own page, which are the two carriers of
-- §6's three that a room without a transcript can have.

CREATE OR REPLACE FUNCTION grant_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". An administrator standing outside a private
  -- voice channel is not among the people whose call this is.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels
                  WHERE id = p_channel AND channel_type = 'voice') THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_grants (channel_id, bot_id, granted_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_grants
   WHERE channel_id = p_channel AND bot_id = p_bot;

  -- The row is only half of it: a bot already in the call holds a token whose
  -- grant said `canSubscribe`, and a token is good for its hour no matter what
  -- this table says afterwards. The `set_bot_voice_listen` edge function pushes
  -- the new permission onto the live connection, the same way `moderate_user`
  -- does for a mute — which is the bug that taught us the row alone is not the
  -- feature.
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION grant_bot_voice_listen(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_voice_listen(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_voice_listen(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_voice_listen(UUID, UUID) TO authenticated;

-- ============================================================
-- 3. A channel that becomes private
-- ============================================================
-- The same re-decision 030 makes for text keys. Whoever granted this was
-- looking at a room the whole server could walk into; a room with a door is a
-- different question, and it should be asked again rather than inherited.

CREATE OR REPLACE FUNCTION drop_bot_voice_grants_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_grants WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS channels_drop_bot_voice_grants ON channels;
CREATE TRIGGER channels_drop_bot_voice_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_grants_when_closed();

-- ============================================================
-- 4. What a client draws the recording light from
-- ============================================================
-- The table is readable directly, but the marker needs a name rather than an
-- id, and joining `users` from every client that draws a channel row is a
-- second query per channel. One view, one round trip.

CREATE OR REPLACE VIEW voice_listeners
  WITH (security_invoker = true) AS
  SELECT g.channel_id,
         g.bot_id,
         u.display_name AS bot_name,
         g.granted_at
    FROM bot_voice_grants g
    JOIN users u ON u.id = g.bot_id
   WHERE NOT u.is_banned;

COMMENT ON VIEW voice_listeners IS
  'Bots that can hear each voice channel, with the name to show. '
  'security_invoker, so bot_voice_grants_select is what decides who sees it.';

REVOKE ALL ON voice_listeners FROM anon;
GRANT SELECT ON voice_listeners TO authenticated;
