-- ============================================================
-- Rift self-hosted server — 053: unread counts work out the caller's
-- channels once
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members and 300 channels, for a member behind in 93.
--
-- `unread_counts`, which the app asks on every open, ran as the caller and
-- counted channel by channel: for each of the 301 channels it may see, a
-- statement for where the unread mail starts, and for each of the 93 with
-- some, a statement counting it. Each of those reads `messages`, so each one
-- ran `messages_select`, and that builds the caller's readable channels
-- (`app.visible_channels`) afresh for every statement: about 0.4 ms, some
-- 400 times. 137 ms of the call was that list being made again.
--
-- Building the list from the caller's own rows, as the review suggested,
-- made it no cheaper (0.52 → 0.58 ms): what costs is making it at all, once
-- per statement.
--
-- So `unread_counts` now runs as the server and works the caller out once:
-- who they are, whether they are a bot, and the channels they may read,
-- which is the set `channels_select` and `messages_select` both test against.
-- The loop walks those channels, and each count asks of a row exactly what
-- the policy would have asked of it there: somebody else's ephemeral reply
-- is not the caller's, and a bot reads only what was sent to it or sealed
-- under a key version it was given (`app.bot_reads_version`, looked up once
-- per channel). The channel-by-channel shape stays, for the reasons the
-- baseline's copy of this function gives.
--
-- 137 → 7 ms for that member. A bot, which the app never is but a call could
-- come from, had every message it may not read checked by a function: one
-- went from 44 s to 31 ms.
--
-- Who sees what is unchanged: the same counts compared for 107 members
-- (bots, banned members, members of private channels, others at random) and
-- 1,213 channel badges, with ephemeral replies and messages to a bot added
-- for the comparison. The DM half and the preferences are as in 051.

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me       UUID  := auth.uid();
  v_bot      BOOLEAN := app.is_bot();
  v_visible  UUID[]  := app.visible_channels();
  v_channels JSONB := '{}'::jsonb;
  v_mentions JSONB := '{}'::jsonb;
  v_chan     RECORD;
  v_cursor   BIGINT;
  v_first    BIGINT;
  v_n        INTEGER;
  v_named    INTEGER;
  v_from     INTEGER;
BEGIN
  -- The channels the caller may see, the set `channels_select` and
  -- `messages_select` both test against, gathered once (see the header).
  FOR v_chan IN
    SELECT c.id, COALESCE(r.last_read_id, 0) AS cursor
      FROM channels c
      LEFT JOIN read_state r
        ON r.user_id = v_me AND r.scope = 'channel' AND r.scope_id = c.id
     WHERE c.id = ANY (v_visible)
  LOOP
    v_cursor := v_chan.cursor;

    -- The floor that keeps the walk on `idx_messages_channel` (see the
    -- baseline's copy of this function for the plan it avoids). It may now
    -- be a message the caller cannot see, which changes nothing: it is only
    -- a floor, and the count below asks of each row what the policy asked.
    SELECT min(m.id) INTO v_first
      FROM messages m
     WHERE m.channel_id = v_chan.id AND m.id > v_cursor;

    IF v_first IS NULL THEN
      CONTINUE;
    END IF;

    -- A bot reads what is sealed under a key it was given, from the version
    -- it was given it at (`app.bot_reads_version`), looked up once here
    -- rather than for each row; null for anybody else, and for a bot never
    -- given this channel's key.
    v_from := NULL;
    IF v_bot THEN
      SELECT g.from_key_version INTO v_from FROM bot_channel_keys g
       WHERE g.channel_id = v_chan.id AND g.bot_id = v_me;
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
         -- What `messages_select` asks of a row in a channel the caller may
         -- see: somebody else's ephemeral reply is not theirs, and a bot
         -- reads only what was sent to it or sealed under a key it was given.
         AND (m.ephemeral_for IS NULL OR m.ephemeral_for = v_me)
         AND (NOT v_bot OR m.to_bot = v_me OR m.key_version >= v_from)
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

COMMENT ON FUNCTION unread_counts() IS
  'Badges and notification levels in one answer: {channels, mentions, dms, '
  'prefs}. Channel counts stop at unread_cap(); mentions are counted among them.';

-- Now SECURITY DEFINER, so the grants are said again rather than inherited.
REVOKE ALL ON FUNCTION unread_counts() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;
