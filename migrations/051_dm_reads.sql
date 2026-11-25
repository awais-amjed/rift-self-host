-- ============================================================
-- Rift self-hosted server — 051: a conversation is read off its own index
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 25–26 on a test
-- database where one member has 300 conversations: 22,500 messages sent and
-- 22,500 received.
--
-- A conversation has an index of its own, `idx_dm_messages_pair` (the pair,
-- lowest id first, then the message id), and nothing that reads one used it.
-- Each asked "sent by me to them, or by them to me", which no index answers
-- in order, so Postgres gathered every message the caller had ever sent or
-- received and sorted out the one conversation:
--
--   * The DM page. 4 ms for a conversation of 75 messages, but it read all
--     45,000 of the caller's messages to find them, and a conversation of a
--     hundred thousand would be read and sorted in full for every page.
--   * The DM half of `unread_counts`: 341 ms of its 417, walking all 45,000
--     to find 18 unread, and asking `app.dm_is_request` of each one.
--   * `mark_all_read`: one grouped walk over everything received.
--   * `mark_read` on a conversation without an id (`0`, "up to the newest"),
--     and the ring's `has_unread_before`: everything received, newest first,
--     until one from that person.
--
-- Now:
--
--   * `dm_messages_page` reads a page of one conversation off the pair index,
--     the way `channel_messages` reads a channel. The app asks it, and asks a
--     server from before it the old way.
--   * Unread DMs are counted from `dm_conversation_heads`, the caller's own
--     conversation list: a conversation whose newest message is not past the
--     caller's cursor is skipped without reading it, and the rest are counted
--     off the pair index, up to `unread_cap()` as a channel is. A request has
--     no head on the recipient's side until it is accepted, which is exactly
--     when it starts to count, as before.
--   * `mark_all_read` moves the cursor of every conversation in that list,
--     and of every request waiting on the caller, which it marked before too.
--   * `mark_read` and `has_unread_before` find a person's newest message off
--     the pair index. `mark_read` also writes nothing when the cursor would
--     not move, which is what the app asks on every focus.
--
-- Who sees what is unchanged. The reads below are SECURITY DEFINER, and each
-- reads only the conversation between the caller and one other member, which
-- is what `dm_messages_select` lets the caller read (sender or recipient).
-- They cannot be written as the caller: under the policy, Postgres gathers
-- every message the caller has sent or received to apply it, beside the pair
-- index, and that is the walk this file removes. Measured with one
-- conversation of 100,000 messages: a page took 103 ms written as the
-- caller, 80 ms the old way, and 0.1 ms as it is here.

-- ── A page of one conversation ──────────────────────────────
-- Branched rather than `p_before IS NULL OR id < p_before`: a disjunction is
-- never an index condition, and the index is the point. Newest first, or
-- oldest first from `p_after`, as `channel_messages` answers. Embeds and
-- computed columns a client selects on top (`reaction_counts`, the sender,
-- the pin) are read as the caller, as before.
CREATE OR REPLACE FUNCTION dm_messages_page(
  p_peer   UUID,
  p_before BIGINT  DEFAULT NULL,
  p_after  BIGINT  DEFAULT NULL,
  p_limit  INTEGER DEFAULT 51
) RETURNS SETOF dm_messages
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me    UUID    := auth.uid();
  v_low   UUID    := LEAST(v_me, p_peer);
  v_high  UUID    := GREATEST(v_me, p_peer);
  -- The clamp `channel_messages` uses, for the same reason.
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 51), 1), 101);
BEGIN
  IF v_me IS NULL OR p_peer IS NULL THEN RETURN; END IF;

  IF p_after IS NOT NULL THEN
    RETURN QUERY
    SELECT d.* FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = v_low
       AND GREATEST(d.sender_id, d.recipient_id) = v_high
       AND d.id > p_after
     ORDER BY d.id LIMIT v_limit;
  ELSIF p_before IS NOT NULL THEN
    RETURN QUERY
    SELECT d.* FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = v_low
       AND GREATEST(d.sender_id, d.recipient_id) = v_high
       AND d.id < p_before
     ORDER BY d.id DESC LIMIT v_limit;
  ELSE
    RETURN QUERY
    SELECT d.* FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = v_low
       AND GREATEST(d.sender_id, d.recipient_id) = v_high
     ORDER BY d.id DESC LIMIT v_limit;
  END IF;
END $$;

COMMENT ON FUNCTION dm_messages_page(UUID, BIGINT, BIGINT, INTEGER) IS
  'One page of the caller''s conversation with p_peer, newest first, or oldest '
  'first from p_after, read off idx_dm_messages_pair.';

-- ── One person's messages to the caller ─────────────────────
-- The newest, and how many are past a cursor: what marking a conversation
-- read and its badge ask. Each reads only messages from p_peer to the caller.
CREATE OR REPLACE FUNCTION app.dm_newest_from(p_peer UUID) RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT max(d.id) FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(auth.uid(), p_peer)
     AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(auth.uid(), p_peer)
     AND d.sender_id = p_peer
$$;

-- Counted up to `unread_cap()`, as a channel is: the badge says "99+" past
-- ninety-nine, and 50,000 unread from one person took 70 ms to count in full.
CREATE OR REPLACE FUNCTION app.dm_unread_from(p_peer UUID, p_after BIGINT)
  RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT count(*) FROM (
    SELECT 1 FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(auth.uid(), p_peer)
       AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(auth.uid(), p_peer)
       AND d.sender_id = p_peer
       AND d.id > p_after
     ORDER BY d.id
     LIMIT unread_cap()) capped
$$;

COMMENT ON FUNCTION app.dm_newest_from(UUID) IS
  'The id of the newest message p_peer sent the caller, or null.';
COMMENT ON FUNCTION app.dm_unread_from(UUID, BIGINT) IS
  'How many messages p_peer sent the caller after p_after, up to unread_cap().';

-- ── Requests waiting on the caller ──────────────────────────
-- Who has asked the caller and not been answered (or been put away). Members
-- cannot read `dm_links`; this is the part of it the app already shows them
-- as their requests. `mark_all_read` marks these read, as it always has.
CREATE OR REPLACE FUNCTION app.dm_requests_to_me() RETURNS SETOF UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT l.opened_by FROM dm_links l
   WHERE l.user_low = auth.uid() AND l.status <> 'open'
     AND l.opened_by <> auth.uid()
  UNION ALL
  SELECT l.opened_by FROM dm_links l
   WHERE l.user_high = auth.uid() AND l.status <> 'open'
     AND l.opened_by <> auth.uid()
$$;

COMMENT ON FUNCTION app.dm_requests_to_me() IS
  'The members whose DM request to the caller is waiting or was put away.';

-- ── Moving a cursor ─────────────────────────────────────────
-- As before, with two changes: "up to the newest" in a conversation is found
-- off the pair index, and a cursor that would not move is not written (the
-- app marks a conversation read every time it is focused).
CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_me     UUID   := auth.uid();
  v_target BIGINT := p_last_read_id;
  v_now    BIGINT;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    IF p_scope = 'channel' THEN
      SELECT COALESCE(max(m.id), 0) INTO v_target
        FROM messages m WHERE m.channel_id = p_scope_id;
    ELSE
      v_target := COALESCE(app.dm_newest_from(p_scope_id), 0);
    END IF;
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (v_me, p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = EXCLUDED.last_read_id,
              updated_at   = now()
        WHERE read_state.last_read_id < EXCLUDED.last_read_id
    RETURNING last_read_id INTO v_now;

  -- Nothing written: the cursor was already there or past it.
  IF v_now IS NULL THEN
    SELECT r.last_read_id INTO v_now
      FROM read_state r
     WHERE r.user_id = v_me AND r.scope = p_scope AND r.scope_id = p_scope_id;
  END IF;
  RETURN v_now;
END; $$;

-- "Mark all as read": every channel as before; every conversation in the
-- caller's list whose newest message is past their cursor, and every request
-- waiting on them, each moved to the newest message from that person.
CREATE OR REPLACE FUNCTION mark_all_read() RETURNS VOID
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT v_me, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();

  WITH peers AS (
    SELECT h.peer_id AS peer
      FROM dm_conversation_heads h
      LEFT JOIN read_state r
        ON r.user_id = v_me AND r.scope = 'dm' AND r.scope_id = h.peer_id
     WHERE h.user_id = v_me
       AND h.last_message_id > COALESCE(r.last_read_id, 0)
    UNION
    SELECT q.peer FROM app.dm_requests_to_me() AS q(peer)
  ), newest AS MATERIALIZED (
    SELECT p.peer, app.dm_newest_from(p.peer) AS id FROM peers p
  )
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT v_me, 'dm', n.peer, n.id
    FROM newest n
   WHERE n.id IS NOT NULL
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();
END; $$;

-- ── Whether to ring ─────────────────────────────────────────
-- The DM half asks the pair index for the newest earlier message from that
-- person past the cursor; the channel half is unchanged.
CREATE OR REPLACE FUNCTION has_unread_before(
  p_user_id UUID, p_scope read_scope, p_scope_id UUID, p_before BIGINT
) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT CASE p_scope
    WHEN 'channel' THEN EXISTS (
      SELECT 1 FROM messages m
       WHERE m.channel_id = p_scope_id
         AND m.sender_id <> p_user_id
         AND m.id < p_before
         AND m.id > COALESCE((SELECT r.last_read_id FROM read_state r
                               WHERE r.user_id = p_user_id AND r.scope = 'channel'
                                 AND r.scope_id = p_scope_id), 0))
    ELSE EXISTS (
      SELECT 1 FROM dm_messages d
       WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(p_user_id, p_scope_id)
         AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(p_user_id, p_scope_id)
         AND d.sender_id = p_scope_id
         AND d.id < p_before
         AND d.id > COALESCE((SELECT r.last_read_id FROM read_state r
                               WHERE r.user_id = p_user_id AND r.scope = 'dm'
                                 AND r.scope_id = p_scope_id), 0))
  END;
$$;

-- ── Badges ──────────────────────────────────────────────────
-- The 034 body; only `dms` is new.
CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_me       UUID  := auth.uid();
  v_channels JSONB := '{}'::jsonb;
  v_mentions JSONB := '{}'::jsonb;
  v_chan     RECORD;
  v_cursor   BIGINT;
  v_first    BIGINT;
  v_n        INTEGER;
  v_named    INTEGER;
BEGIN
  -- SECURITY INVOKER, so this is the channels the caller may see and no
  -- others: `channels_select` decides, once per channel, instead of
  -- `messages_select` deciding once per message.
  FOR v_chan IN SELECT c.id FROM channels c LOOP
    SELECT r.last_read_id INTO v_cursor
      FROM read_state r
     WHERE r.user_id = v_me
       AND r.scope   = 'channel'
       AND r.scope_id = v_chan.id;
    v_cursor := COALESCE(v_cursor, 0);

    -- The floor that keeps the walk on `idx_messages_channel` (see the
    -- baseline's copy of this function for the plan it avoids).
    SELECT min(m.id) INTO v_first
      FROM messages m
     WHERE m.channel_id = v_chan.id AND m.id > v_cursor;

    IF v_first IS NULL THEN
      CONTINUE;
    END IF;

    SELECT count(*),
           count(*) FILTER (WHERE capped.named)
      INTO v_n, v_named
      FROM (
      SELECT (m.mentions_all OR v_me = ANY (m.mentions)) AS named
        FROM messages m
       WHERE m.channel_id = v_chan.id
         AND m.id > v_cursor
         AND m.id >= v_first
         -- IS DISTINCT FROM, not <>: a webhook's sender is NULL.
         AND m.sender_id IS DISTINCT FROM v_me
         -- A press is not unread mail.
         AND NOT m.is_interaction
       ORDER BY m.id
       LIMIT unread_cap()
    ) capped;

    IF v_n > 0 THEN
      v_channels := v_channels || jsonb_build_object(v_chan.id::TEXT, v_n);
    END IF;
    IF v_named > 0 THEN
      v_mentions := v_mentions || jsonb_build_object(v_chan.id::TEXT, v_named);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'channels', v_channels,
    'mentions', v_mentions,
    -- One row per conversation in the caller's list. A conversation read up
    -- to its newest message is skipped without reading it; the rest count
    -- that person's messages past the cursor off the pair index. A request
    -- is not mail until it is accepted: the recipient has no head for it
    -- until then, and an ignored one asked again is still a request.
    'dms', COALESCE((
      WITH behind AS (
        SELECT h.peer_id AS peer, COALESCE(r.last_read_id, 0) AS cursor
          FROM dm_conversation_heads h
          LEFT JOIN read_state r
            ON r.user_id = v_me AND r.scope = 'dm' AND r.scope_id = h.peer_id
         WHERE h.user_id = v_me
           AND h.last_message_id > COALESCE(r.last_read_id, 0)
      ), counted AS MATERIALIZED (
        SELECT b.peer, app.dm_unread_from(b.peer, b.cursor) AS n FROM behind b
      )
      SELECT jsonb_object_agg(c.peer, c.n) FROM counted c
       WHERE c.n > 0 AND NOT app.dm_is_request(c.peer, v_me)), '{}'::jsonb),
    -- Only what has been set: an absent key means "no opinion here, ask the
    -- next scope out".
    'prefs', jsonb_build_object(
      'servers', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = v_me AND p.scope = 'server'), '{}'::jsonb),
      'channels', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = v_me AND p.scope = 'channel'), '{}'::jsonb),
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = v_me AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

-- ── Grants ──────────────────────────────────────────────────
-- mark_read, mark_all_read, has_unread_before and unread_counts keep the
-- grants they had (CREATE OR REPLACE).
REVOKE ALL ON FUNCTION dm_messages_page(UUID, BIGINT, BIGINT, INTEGER) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.dm_requests_to_me() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.dm_newest_from(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.dm_unread_from(UUID, BIGINT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION dm_messages_page(UUID, BIGINT, BIGINT, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION app.dm_requests_to_me() TO authenticated;
GRANT EXECUTE ON FUNCTION app.dm_newest_from(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION app.dm_unread_from(UUID, BIGINT) TO authenticated;
