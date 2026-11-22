-- ============================================================
-- Rift self-hosted server — 034: unread mentions, counted
-- ============================================================
-- Found by the owner on Nov 23 2026.
--
-- `unread_counts()` said how many messages each channel had unread and
-- nothing about which of them named the caller. So the app's server chip
-- added up every unread message in every channel that was not muted, and a
-- channel left at "Only @mentions" — what every channel is until somebody
-- changes it — put a "1" on its server for a message that named nobody. The
-- chip is the app saying "you are wanted over there", and a mentions-only
-- channel has said when it wants you.
--
-- So the answer gains `mentions`: per channel, how many of the unread
-- messages name the caller or everyone, counted in the same capped walk as the
-- channel's own count (a mention is one of the unread messages, so it can
-- never be more). Absent keys mean none, as in `channels`. The lists are the
-- ones `validate_message_mentions` left on the row, the same ones that ring a
-- phone (`app.channel_ring_targets`); the sender writes them, so a modified
-- client can make a badge that names nobody, as it can make a ring.
--
-- An app reading a server without this key counts every unread message, as
-- it did before.
-- ============================================================

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
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
     WHERE r.user_id = auth.uid()
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

    -- The same capped walk as before; the mentions are counted among the
    -- rows it already reads, so they cost nothing more to find.
    SELECT count(*),
           count(*) FILTER (WHERE capped.named)
      INTO v_n, v_named
      FROM (
      SELECT (m.mentions_all OR auth.uid() = ANY (m.mentions)) AS named
        FROM messages m
       WHERE m.channel_id = v_chan.id
         AND m.id > v_cursor
         AND m.id >= v_first
         -- IS DISTINCT FROM, not <>: a webhook's sender is NULL.
         AND m.sender_id IS DISTINCT FROM auth.uid()
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
    'dms', COALESCE((
      SELECT jsonb_object_agg(sender_id, n) FROM (
        SELECT d.sender_id, count(*) AS n
          FROM dm_messages d
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'dm'
           AND r.scope_id = d.sender_id
         WHERE d.recipient_id = auth.uid()
           AND d.id > COALESCE(r.last_read_id, 0)
         GROUP BY d.sender_id
      ) d
      -- A request is not mail until it is accepted.
      WHERE NOT app.dm_is_request(d.sender_id, auth.uid())), '{}'::jsonb),
    -- Only what has been set: an absent key means "no opinion here, ask the
    -- next scope out".
    'prefs', jsonb_build_object(
      'servers', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'server'), '{}'::jsonb),
      'channels', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'channel'), '{}'::jsonb),
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

COMMENT ON FUNCTION unread_counts() IS
  'Badges and notification levels in one answer: {channels, mentions, dms, '
  'prefs}. Channel counts stop at unread_cap(); mentions are counted among them.';

-- CREATE OR REPLACE keeps the grants the baseline gave it (authenticated
-- only), so there is nothing to revoke or grant again here.
