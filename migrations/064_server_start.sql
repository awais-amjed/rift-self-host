-- ============================================================
-- Rift self-hosted server — 064: what an app loads first, in one call
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- An app opening a server asked it, one request each, for the unread counts,
-- the member list's first frame, the soundboard, the bots allowed to listen
-- in each voice channel and the bots summoned into them: five requests for
-- every server on the rail, at every start, and again from every app at once
-- when a server's Realtime comes back. The server on screen asked three more
-- for its DM list, its waiting requests and who the member has blocked, at
-- every click on the rail as well.
--
--   * `server_start(p_member_limit)` answers the first five together. The
--     app's first loads share it, and keep their own calls for what they
--     read again later.
--   * `dm_lists()` answers the three DM lists together.
--
-- Both run as the caller (SECURITY INVOKER) and compose what was already
-- there: `unread_counts`, `member_sidebar`, `dm_conversations` and
-- `dm_requests` keep their own rules, and the tables and views read here
-- answer under the same policies the app's own reads met. Nothing is shown
-- that those calls did not show.
--
-- `server_start` also says `sweeps_itself`. From this release the console
-- runs the attachment sweep on a timer, so an app that hears it stops asking
-- `sweep_attachments` every time it opens the server. The function stays,
-- for apps that have not moved.

-- ── An app's first loads ────────────────────────────────────
CREATE OR REPLACE FUNCTION public.server_start(p_member_limit INTEGER DEFAULT 51)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
BEGIN
  RETURN jsonb_build_object(
    'unread',  unread_counts(),
    'sidebar', member_sidebar(LEAST(GREATEST(p_member_limit, 1), 201)),
    'sounds', (
      SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'id',          s.id,
               'name',        s.name,
               'emoji',       s.emoji,
               'object_path', s.object_path,
               'duration_ms', s.duration_ms,
               'bytes',       s.bytes,
               'created_by',  s.created_by,
               'created_at',  s.created_at) ORDER BY s.created_at), '[]'::jsonb)
        FROM soundboard_sounds s),
    'listeners', (
      SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'channel_id', l.channel_id,
               'bot_id',     l.bot_id,
               'bot_name',   l.bot_name) ORDER BY l.bot_name), '[]'::jsonb)
        FROM voice_listeners l),
    'summons', (
      SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'channel_id', v.channel_id,
               'bot_id',     v.bot_id,
               'bot_name',   v.bot_name) ORDER BY v.bot_name), '[]'::jsonb)
        FROM voice_summons v),
    'sweeps_itself', true);
END $$;

COMMENT ON FUNCTION public.server_start(INTEGER) IS
  'What an app loads first on a server, in one call: unread counts, the '
  'member sidebar, the soundboard, voice listeners and summons. Runs as '
  'the caller; each part answers as its own call does.';

-- ── The DM lists ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.dm_lists() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'conversations', dm_conversations(),
    'requests',      dm_requests(),
    'blocks', (SELECT COALESCE(jsonb_agg(b.blocked_id), '[]'::jsonb)
                 FROM member_blocks b
                WHERE b.blocker_id = auth.uid()));
$$;

COMMENT ON FUNCTION public.dm_lists() IS
  'The caller''s first page of DM conversations, the requests waiting on '
  'them and who they have blocked, in one call. Runs as the caller.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.server_start(INTEGER) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.dm_lists() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.server_start(INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION public.dm_lists() TO authenticated;
