-- ============================================================
-- Rift self-hosted server — 054: a ring reads only the cursors that are
-- caught up
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members.
--
-- `app.channel_ring_targets` finds who is caught up in a channel, so a new
-- message rings their phones, by reading `read_state` along
-- `idx_read_state_caught_up` from a lower bound. The bound was the newest
-- message from anybody other than the last sender, because for the sender
-- themself that is the one that matters. In a channel only one person writes
-- in, an announcements channel, there is no such message: the bound became 0,
-- and every member's cursor there was read and checked, caught up or not.
--
-- So the two are asked apart: everybody at or past the newest message, along
-- the index from there, and the last sender's own cursor by the primary key.
-- Who is rung is the same; the comparison is made exactly as before, for
-- each member, only the rows that cannot pass are no longer read.
--
-- With 2,475 of 47,981 members caught up in such a channel: 45,506 cursors
-- read and dropped → none, 6.1 → 2.9 ms on a warm cache, 11 → 8.5 ms for the
-- whole function. The seeded cursors lie together on disk; on a server where
-- each member's was written at a different time, the old way read about a
-- page for every member of the channel.

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
    -- write. For everybody but its sender that is the newest message itself,
    -- and the index walks only the cursors at or past it.
    SELECT r.user_id
      FROM read_state r
     WHERE r.scope = 'channel'
       AND r.scope_id = p_message.channel_id
       AND r.last_read_id >= v_t.o_newest
    UNION
    -- Its sender needs only to have read the newest one somebody else wrote,
    -- and is one row, found by the primary key.
    SELECT r.user_id
      FROM read_state r
     WHERE r.user_id = v_t.o_newest_by
       AND r.scope = 'channel'
       AND r.scope_id = p_message.channel_id
       AND r.last_read_id >= COALESCE(v_t.o_newest_other, 0)
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

-- Nobody calls it but the trigger.
REVOKE ALL ON FUNCTION app.channel_ring_targets(messages) FROM PUBLIC, anon, authenticated;
