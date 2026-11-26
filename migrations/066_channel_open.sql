-- ============================================================
-- Rift self-hosted server — 066: opening a channel in one call
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- Opening a channel asked the server five things at once: the newest page,
-- what the bar above the message box holds, the caller's keys, the bots
-- holding a key to it and the bots a `/` there reaches. Five requests, each
-- signed in and run on its own, for one click, and every switch between
-- channels paid all five.
--
--   * `channel_open(p_channel, p_limit, p_bot_limit)` answers all five:
--     `{messages, live, key, key_error, listeners, bots}`. It runs as the
--     caller, so every row is still decided where it always was: the page and
--     the bar by `channel_messages` and `app.channel_live_ids` with the rows
--     under `messages_select`, the listeners under the view's policies, the bots by
--     `list_members`, the keys by `my_channel_key`. A refusal from the keys
--     (`channel_not_found`) comes back as `key_error` beside the rest rather
--     than failing it, as it did when they were asked apart.
--   * The page and the bar come back as the app selects them through
--     PostgREST: each message's columns, its sender's name, key and picture,
--     its reaction counts and its pin.
--
-- An app asks `channel_open` and, on a server from before it, asks the five
-- apart as it did.

-- ── Opening a channel ───────────────────────────────────────
-- Volatile only because `my_channel_key` is. The page asks one row past
-- [p_limit]'s page as the app always has, and [p_bot_limit] likewise: an app
-- that gets that many bots back reads the rest as it did.
CREATE OR REPLACE FUNCTION public.channel_open(
  p_channel   UUID,
  p_limit     INTEGER DEFAULT 51,
  p_bot_limit INTEGER DEFAULT 51
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_page      JSONB;
  v_live      JSONB;
  v_key       JSONB;
  v_key_error TEXT;
  v_listeners JSONB;
  v_bots      JSONB;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  -- The page and the bar in one pass, each row in the shape the app's read
  -- selects, with its three embeds: `sender` (null for a webhook's message,
  -- which has no sender row), `reactions` from `reaction_counts`, and
  -- `message_pins` (one-to-one: an object or null). The sender and the pin
  -- are read under their policies, as PostgREST's embeds are. Written out
  -- here rather than in a function of their own: one the planner cannot fold
  -- in ran as a call of its own for every row, and the page took 11 ms
  -- rather than 2. The bar is `channel_live_messages` written out too: as
  -- an SQL function it is planned again on every call, `messages_select`
  -- and all, which cost 2 ms to read nothing; here the plan is kept.
  SELECT COALESCE(jsonb_agg(r.j ORDER BY r.id DESC) FILTER (WHERE r.live), '[]'::jsonb),
         COALESCE(jsonb_agg(r.j ORDER BY r.id DESC) FILTER (WHERE NOT r.live), '[]'::jsonb)
    INTO v_live, v_page
    FROM (
      SELECT m.live, m.id, jsonb_build_object(
        'id', m.id, 'created_at', m.created_at, 'channel_id', m.channel_id,
        'sender_id', m.sender_id, 'ciphertext', m.ciphertext,
        'nonce', m.nonce, 'signature', m.signature,
        'key_version', m.key_version, 'edited_at', m.edited_at,
        'webhook_id', m.webhook_id, 'origin_name', m.origin_name,
        'is_system', m.is_system, 'to_bot', m.to_bot, 'blocks', m.blocks,
        'is_interaction', m.is_interaction, 'reply_to', m.reply_to,
        'ephemeral_for', m.ephemeral_for, 'poll', m.poll,
        'mentions_all', m.mentions_all,
        'sender', (SELECT jsonb_build_object('display_name', u.display_name,
                                             'public_key', u.public_key,
                                             'avatar_path', u.avatar_path)
                     FROM users u WHERE u.id = m.sender_id),
        'reactions', app.reaction_counts_of('channel', m.id),
        'message_pins', (SELECT jsonb_build_object('pinned_at', p.pinned_at)
                           FROM message_pins p WHERE p.message_id = m.id)) AS j
        FROM (SELECT FALSE AS live, c.*
                FROM channel_messages(p_channel, NULL, NULL, p_limit) AS c
              UNION ALL
              SELECT TRUE, x.*
                FROM app.channel_live_ids(p_channel) AS l(id)
                JOIN messages x ON x.id = l.id) m
    ) r;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'bot_id', l.bot_id, 'username', l.username,
           'display_name', l.display_name,
           'granted_by_name', l.granted_by_name,
           'granted_at', l.granted_at) ORDER BY l.display_name), '[]'::jsonb)
    INTO v_listeners
    FROM channel_bot_listeners l
   WHERE l.channel_id = p_channel;

  -- In the page's own order, which is the roster's.
  SELECT COALESCE(jsonb_agg(to_jsonb(d)
           ORDER BY app.member_sort_key(d.display_name), d.id), '[]'::jsonb)
    INTO v_bots
    FROM list_members(p_channel, TRUE, FALSE, NULL, NULL, p_bot_limit) AS d;

  BEGIN
    v_key := my_channel_key(p_channel);
  EXCEPTION WHEN raise_exception THEN
    v_key_error := SQLERRM;
  END;

  RETURN jsonb_build_object(
    'messages', v_page,
    'live', v_live,
    'key', v_key,
    'key_error', v_key_error,
    'listeners', v_listeners,
    'bots', v_bots);
END $$;

COMMENT ON FUNCTION public.channel_open(UUID, INTEGER, INTEGER) IS
  'Everything a channel needs when it opens: its newest page, its bar, the '
  'caller''s keys (or why not), the bots holding a key to it and the bots a '
  '/ there reaches. Read as the caller; rows are still subject to their '
  'policies.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.channel_open(UUID, INTEGER, INTEGER) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.channel_open(UUID, INTEGER, INTEGER) TO authenticated;
