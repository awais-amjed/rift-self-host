-- ============================================================
-- Rift self-hosted server — 083: a channel's poll counts come with it
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (its finding 5, left
-- open by 066).
--
-- Opening a channel was `channel_open`, then, once the page had come back
-- and been opened, `poll_tallies` for the polls on it and in the bar: a
-- second round trip after the first, and the counts drawn a moment after
-- the polls. `channel_open` now answers `tallies` too, in `poll_tallies`'s
-- shape (`{message_id: {counts, voters, mine}}`), for the polls among the
-- rows it returns; `{}` when there are none. The function is otherwise as
-- 066 wrote it. An app that finds no `tallies` (a server before this) asks
-- `poll_tallies` as before.
--
-- `mark_read` stays its own call: the app marks a channel read only while
-- it is on screen, which the read of the channel does not know, and since
-- 074 a mark that moves nothing writes nothing.

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
  v_tallies   JSONB;
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

  -- How the polls on the page and in the bar stand, which the app asked
  -- next, once the rows had come back (083).
  SELECT poll_tallies(array_agg((e->>'id')::BIGINT))
    INTO v_tallies
    FROM jsonb_array_elements(v_page || v_live) AS e
   WHERE jsonb_typeof(e->'poll') = 'object';

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
    'bots', v_bots,
    'tallies', COALESCE(v_tallies, '{}'::jsonb));
END $$;

COMMENT ON FUNCTION public.channel_open(UUID, INTEGER, INTEGER) IS
  'Everything a channel needs when it opens: its newest page, its bar, the '
  'caller''s keys (or why not), the bots holding a key to it, the bots a '
  '/ there reaches, and how the polls among those rows stand. Read as the '
  'caller; rows are still subject to their policies.';
