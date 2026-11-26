-- ============================================================
-- Rift self-hosted server — 086: opening a DM conversation in one request
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (its #12).
--
-- Opening a conversation with another member was three requests from the
-- app, one after another where they could not overlap: where the two stand
-- (`dm_link_state`), the newest page (`dm_messages_page`, with its sender,
-- reaction counts and pin embedded), and, once that page was on screen, the
-- calls beside it (`dm_call_log`, from the oldest message shown when there is
-- more above it).
--
--   * `dm_open(p_peer, p_limit)` answers all three: `{link_state, messages,
--     calls, calls_since_id}`. Each part is what its own function answers,
--     read under the same policies: it is SECURITY INVOKER and calls them.
--     `messages` is newest first, each row in the shape the app's page read
--     selects (as `channel_open` builds them), `p_limit` rows at most, one past
--     the page the app shows so it can tell there is more.
--   * `calls` is read from the oldest row the app will show when there is
--     more above it — the row before the extra one — and `calls_since_id`
--     names that row, null when the page is the whole conversation. The app
--     keeps the calls only when the oldest message it shows is that row (a
--     row it dropped as forged moves it) and reads them again otherwise.
--
-- Marking it read is not here. The app marks a conversation read only while
-- it is on screen, which only the app knows, and `mark_read` writes nothing
-- for a conversation already read (074).

CREATE OR REPLACE FUNCTION public.dm_open(
  p_peer  UUID,
  p_limit INTEGER DEFAULT 51
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  -- `dm_messages_page`'s clamp, so the edge row below is the one it gave.
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 51), 1), 101);
  v_page  JSONB;
  v_n     INTEGER;
  v_edge  JSONB;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  -- Each row with its three embeds, as the app's read selects them and as
  -- `channel_open` writes them out: `sender` (read under its policy, as
  -- PostgREST's embed is), `reactions` from the counts, and
  -- `dm_message_pins` (one-to-one: an object or null).
  SELECT COALESCE(jsonb_agg(r.j ORDER BY r.id DESC), '[]'::jsonb), count(*)
    INTO v_page, v_n
    FROM (
      SELECT d.id, jsonb_build_object(
        'id', d.id, 'created_at', d.created_at,
        'sender_id', d.sender_id, 'recipient_id', d.recipient_id,
        'ciphertext', d.ciphertext, 'nonce', d.nonce, 'signature', d.signature,
        'key_version', d.key_version, 'edited_at', d.edited_at,
        'sender', (SELECT jsonb_build_object('display_name', u.display_name,
                                             'public_key', u.public_key,
                                             'avatar_path', u.avatar_path)
                     FROM users u WHERE u.id = d.sender_id),
        'reactions', app.reaction_counts_of('dm', d.id),
        'dm_message_pins', (SELECT jsonb_build_object('pinned_at', p.pinned_at)
                              FROM dm_message_pins p WHERE p.message_id = d.id)) AS j
        FROM dm_messages_page(p_peer, NULL, NULL, v_limit) AS d
    ) r;

  -- More above the page: the calls start at its oldest shown row, the one
  -- before the extra.
  IF v_n >= v_limit AND v_limit > 1 THEN
    v_edge := v_page -> (v_limit - 2);
  END IF;

  RETURN jsonb_build_object(
    'link_state', dm_link_state(p_peer),
    'messages', v_page,
    'calls', dm_call_log(p_peer, (v_edge ->> 'created_at')::timestamptz),
    'calls_since_id', (v_edge ->> 'id')::bigint);
END $$;

COMMENT ON FUNCTION public.dm_open(UUID, INTEGER) IS
  'Everything a DM conversation shows when it opens, in one request: '
  'dm_link_state, the newest dm_messages_page with its embeds, and the '
  'dm_call_log beside that page (from calls_since_id''s row when there is '
  'more above it). Read as the caller.';

REVOKE ALL ON FUNCTION public.dm_open(UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dm_open(UUID, INTEGER) TO authenticated;
