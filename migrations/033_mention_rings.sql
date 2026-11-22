-- ============================================================
-- Rift self-hosted server — 033: a mention rings the phone it names
-- ============================================================
-- Found by a feature review of the app on Nov 23 2026.
--
-- `ring_channel_members` rang only members who were caught up in the
-- channel, which is right for an ordinary message: a phone that already has
-- something unread there reads everything when it wakes, so a second ring
-- adds nothing. A mention is not an ordinary message. With anything unread in
-- the channel — one "hi" from somebody a minute earlier — "@you urgent" rang
-- nobody, and the person named heard about it only once they opened Rift.
--
-- So the members a message names are rung as well, caught up or not, and
-- everybody who can see the channel when it names everyone. Both lists are the
-- ones `validate_message_mentions` left on the row: at most fifty members who
-- can see the channel, and `mentions_all` only from a sender allowed it. The
-- phone still decides what to say from the plaintext, so a mention the text
-- does not make costs a silent wake and nothing else.
--
-- Who is rung moves into `app.channel_ring_targets`, so the suite can ask it
-- without a push relay to send to.
-- ============================================================

CREATE OR REPLACE FUNCTION app.channel_ring_targets(p_message messages)
  RETURNS UUID[] LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_private   BOOLEAN;
  v_eligible  UUID[];
  v_t         RECORD;
  v_targets   UUID[];
BEGIN
  SELECT c.server_id, c.is_private INTO v_server_id, v_private
    FROM channels c WHERE c.id = p_message.channel_id;
  IF v_server_id IS NULL THEN RETURN NULL; END IF;

  -- Eligibility, decided once rather than per member (see the baseline's
  -- `ring_channel_members` for the measurement behind it).
  IF v_private THEN
    v_eligible := app.channel_audience(p_message.channel_id);
    IF v_eligible IS NULL OR cardinality(v_eligible) = 0 THEN RETURN NULL; END IF;
  END IF;

  v_t := app.unread_thresholds(p_message.channel_id, p_message.id);

  IF v_t.o_newest IS NULL OR p_message.mentions_all THEN
    -- The first message in the channel, when nobody can have unread mail
    -- before it, or one naming everyone: everybody eligible.
    SELECT array_agg(u.id) INTO v_targets
      FROM users u
     WHERE u.server_id = v_server_id
       AND u.id IS DISTINCT FROM p_message.sender_id
       AND NOT u.is_banned AND NOT u.is_bot
       AND (p_message.ephemeral_for IS NULL OR u.id = p_message.ephemeral_for)
       AND (NOT v_private OR u.id IN (SELECT unnest(v_eligible)));
    RETURN v_targets;
  END IF;

  SELECT array_agg(c.user_id) INTO v_targets FROM (
    -- Everyone whose cursor is at or past the newest message they did not
    -- write. The first bound is the cheap one and drives the index; the
    -- second is the exact one and is checked on what it returns.
    SELECT r.user_id
      FROM read_state r
     WHERE r.scope = 'channel'
       AND r.scope_id = p_message.channel_id
       AND r.last_read_id >= COALESCE(v_t.o_newest_other, 0)
       AND r.last_read_id >= CASE
             WHEN v_t.o_newest_by IS DISTINCT FROM r.user_id THEN v_t.o_newest
             ELSE COALESCE(v_t.o_newest_other, 0) END
    UNION
    -- The one member who can be caught up with no `read_state` row at all:
    -- when nobody else has ever written here, everything before this
    -- message is theirs, so there is nothing of anybody else's to have
    -- missed.
    SELECT v_t.o_newest_by
     WHERE v_t.o_newest_other IS NULL AND v_t.o_newest_by IS NOT NULL
    UNION
    -- Named in it, whatever they have read.
    SELECT unnest(COALESCE(p_message.mentions, '{}'))
  ) c
  JOIN users u ON u.id = c.user_id
 WHERE u.server_id = v_server_id
   AND u.id IS DISTINCT FROM p_message.sender_id
   AND NOT u.is_banned AND NOT u.is_bot
   AND (p_message.ephemeral_for IS NULL OR u.id = p_message.ephemeral_for)
   AND (NOT v_private OR u.id IN (SELECT unnest(v_eligible)));
  RETURN v_targets;
END $$;

COMMENT ON FUNCTION app.channel_ring_targets(messages) IS
  'Whose phones a new channel message rings: members caught up in the channel, '
  'and the members it names, or everybody who can see it when it names everyone.';

CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  IF NEW.is_interaction THEN RETURN NEW; END IF;

  SELECT c.server_id INTO v_server_id
    FROM channels c WHERE c.id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  PERFORM ring_devices(v_server_id, app.channel_ring_targets(NEW));
  RETURN NEW;
END $$;

COMMENT ON FUNCTION ring_channel_members() IS
  'Wake the phones `app.channel_ring_targets` names for a new channel message. '
  'Push off on the server costs one lookup and nothing else.';

-- Nobody calls it but the trigger, and Supabase grants every new function to
-- `anon` and `authenticated` unless told otherwise.
REVOKE ALL ON FUNCTION app.channel_ring_targets(messages) FROM PUBLIC, anon, authenticated;
