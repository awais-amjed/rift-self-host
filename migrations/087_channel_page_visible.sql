-- ============================================================
-- Rift self-hosted server — 087: a channel's page counts only rows its reader sees
-- ============================================================
-- Found in the live test of Nov 27 2026: scrolling up in a busy channel
-- stopped at the first page, with hundreds of older messages behind it.
--
-- `channel_messages` (and `channel_open`, which reads through it) takes a
-- page as ids first, from `app.channel_page_ids`, and fetches the rows by
-- key under `messages_select`. The ids half checked only that the caller
-- may open the channel, and the policy then dropped what is not theirs to
-- see: a button press between somebody else and a bot, an ephemeral reply
-- somebody else was shown, and for a bot, a message sealed under a key
-- version from before its grant. Asked for a page and one past it (51), a
-- reader got fewer — 47 on the test server — and the app, which tells that
-- there is more from that one extra row, decided the channel began there.
--
--   * `app.channel_page_ids` now picks only ids the policy would show this
--     caller, with the policy's own three per-row rules, so a page is full
--     whenever there is that much the caller may read, and the extra row
--     means what the app takes it to mean.
--   * The rules are the policy's, asked once each and not per row: who the
--     caller is, whether they are a bot, and from which key version a bot's
--     grant reads. The scan stays on `idx_messages_channel`; it reads each
--     row it passes to check it, where it read the index alone, and the
--     rows it returns are fetched again by key in any case.
--   * `messages_select` is unchanged and still decides: this only stops the
--     ids half from spending the page on rows it will not show.

CREATE OR REPLACE FUNCTION app.channel_page_ids(
  p_channel UUID,
  p_before  BIGINT,
  p_after   BIGINT,
  p_limit   INTEGER
) RETURNS SETOF BIGINT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me   UUID := auth.uid();
  v_bot  BOOLEAN;
  -- The oldest key version a bot's grant here reads; null without one.
  v_from INTEGER;
BEGIN
  -- Asked once, not per row, and it is the whole of the channel check.
  -- An outsider gets no rows, which is what the policy gives them too.
  IF NOT app.can_see_channel(p_channel) THEN RETURN; END IF;

  v_bot := app.is_bot();
  IF v_bot THEN
    SELECT min(g.from_key_version) INTO v_from
      FROM bot_channel_keys g
     WHERE g.channel_id = p_channel AND g.bot_id = v_me;
  END IF;

  -- Branched rather than `p_before IS NULL OR x.id < p_before`, for the
  -- reason the member pages are branched: a disjunction is never an index
  -- condition, and the index is the entire point of this function. The
  -- visibility test is the same in each branch: `messages_select`'s three
  -- per-row rules, with what they ask about the caller asked above.
  IF p_after IS NOT NULL THEN
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel AND x.id > p_after
       AND (NOT v_bot OR x.to_bot = v_me OR x.sender_id = v_me
            OR x.key_version >= v_from)
       AND (x.ephemeral_for IS NULL OR x.ephemeral_for = v_me OR x.sender_id = v_me)
       AND (NOT x.is_interaction OR x.sender_id = v_me OR x.to_bot = v_me)
     ORDER BY x.id LIMIT p_limit;
  ELSIF p_before IS NOT NULL THEN
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel AND x.id < p_before
       AND (NOT v_bot OR x.to_bot = v_me OR x.sender_id = v_me
            OR x.key_version >= v_from)
       AND (x.ephemeral_for IS NULL OR x.ephemeral_for = v_me OR x.sender_id = v_me)
       AND (NOT x.is_interaction OR x.sender_id = v_me OR x.to_bot = v_me)
     ORDER BY x.id DESC LIMIT p_limit;
  ELSE
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel
       AND (NOT v_bot OR x.to_bot = v_me OR x.sender_id = v_me
            OR x.key_version >= v_from)
       AND (x.ephemeral_for IS NULL OR x.ephemeral_for = v_me OR x.sender_id = v_me)
       AND (NOT x.is_interaction OR x.sender_id = v_me OR x.to_bot = v_me)
     ORDER BY x.id DESC LIMIT p_limit;
  END IF;
END $$;

COMMENT ON FUNCTION app.channel_page_ids(UUID, BIGINT, BIGINT, INTEGER) IS
  'One page of a channel''s message ids, newest first, or oldest first when '
  'p_after is given, counting only rows messages_select shows the caller. '
  'Nothing but ids, so the read stays on idx_messages_channel; '
  '`channel_messages` turns them into rows under RLS.';
