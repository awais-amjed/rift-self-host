-- ============================================================
-- Rift self-hosted server — 022: what is live in a channel
-- ============================================================
-- A channel's chat now has a bar on top of its message box holding what is
-- live there: every open poll, and a bot's player. Both are messages, and the
-- chat loads one page of them, so a poll posted a hundred messages ago — or
-- a music bot's player that every `/play` since has pushed up the chat — is
-- not in anything the app has. It asks for them here instead.
--
-- Live means one of two things, both already in the clear:
--
--   * a poll whose `closes_at` is still ahead (the question is sealed in the
--     body; its rules are in `messages.poll`, which is what the server reads
--     to refuse a late vote);
--   * a panel whose bot says it is current, with `"live": true` beside `v`
--     and `blocks`. `messages_blocks_shape` already allows the key, so this
--     is a format change and not a schema one. A bot drops it on its last
--     redraw; one that crashed cannot, and the app shows a live panel only
--     while its bot is connected. Only the JSON boolean counts: `"true"`, a
--     string, is not live, the same as the app reads it.
--
-- Built in two halves exactly as `channel_messages` is, for the reason given
-- at `app.channel_page_ids`: the definer half answers in ids from an
-- index and decides only whether the caller may open the channel, and the
-- invoker half fetches each row by primary key with `messages_select` in
-- force. Each lookup has its own partial index, so a big channel with a
-- handful of polls reads a handful of index entries.
--
-- A server without this file still works: the app falls back on what its
-- loaded page holds.
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_messages_polls
  ON messages (channel_id, id) WHERE poll IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_live_panels
  ON messages (channel_id, id) WHERE blocks -> 'live' = 'true'::jsonb;

-- The ids half. Open polls are looked for among the channel's newest 200
-- polls and live panels among its newest 25 — bounds no real channel reaches
-- with open ones, and what keeps a channel of ten thousand old polls from
-- being read whole on every open. `closes_at` is tested here rather than
-- indexed: it is inside a JSON value and moves with every poll's own clock.
CREATE OR REPLACE FUNCTION app.channel_live_ids(p_channel UUID)
RETURNS SETOF BIGINT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_channel) THEN RETURN; END IF;

  RETURN QUERY
  SELECT id FROM (
    SELECT p.id FROM (
      SELECT x.id, x.poll FROM messages x
       WHERE x.channel_id = p_channel AND x.poll IS NOT NULL
       ORDER BY x.id DESC LIMIT 200
    ) p
     WHERE (p.poll ->> 'closes_at')::timestamptz > now()
    UNION
    SELECT b.id FROM (
      SELECT x.id FROM messages x
       WHERE x.channel_id = p_channel AND x.blocks -> 'live' = 'true'::jsonb
       ORDER BY x.id DESC LIMIT 25
    ) b
  ) live
  ORDER BY id DESC LIMIT 25;
END $$;

COMMENT ON FUNCTION app.channel_live_ids(UUID) IS
  'Ids of a channel''s open polls and live panels, newest first, at most 25. '
  'Ids only; `channel_live_messages` turns them into rows under RLS.';

-- The visible half. A row the policy drops — a live panel shown only to
-- somebody else — is simply missing, as it is from a page.
CREATE OR REPLACE FUNCTION channel_live_messages(p_channel UUID)
RETURNS SETOF messages
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.* FROM app.channel_live_ids(p_channel) AS l(id)
    JOIN messages m ON m.id = l.id
   ORDER BY m.id DESC;
$$;

COMMENT ON FUNCTION channel_live_messages(UUID) IS
  'What the bar above a channel''s message box holds: its open polls and its '
  'bots'' live panels, newest first, whatever page the chat has loaded. Rows '
  'are still subject to messages_select.';

-- ============================================================
-- Who may call them
-- ============================================================
REVOKE ALL ON FUNCTION app.channel_live_ids(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION channel_live_messages(UUID) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION channel_live_messages(UUID) TO authenticated;

-- The definer half, which `channel_live_messages` calls and nothing else
-- should; a SECURITY DEFINER function still needs its caller to hold EXECUTE.
GRANT EXECUTE ON FUNCTION app.channel_live_ids(UUID) TO authenticated;
