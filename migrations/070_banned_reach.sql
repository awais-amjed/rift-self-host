-- ============================================================
-- Rift self-hosted server — 070: what a ban or a stranger can still reach
-- ============================================================
-- Found in the security re-review, Nov 26 2026. A ban, and a server marked
-- deleted (057), shut a member out through `app.server_id()`, which answers
-- nothing for them. Three paths never asked it.
--
--   * A bot reads its channels through `app.bot_channels()`, its grants,
--     which a ban leaves in place (only a kick deletes them). A banned bot
--     kept reading every message and every key it had been given, and
--     `app.announce_to_channel` kept telling it about each new one. Both
--     now ask that the bot is still in, on a server not being deleted.
--   * `dm_messages_update_own` asked only that the row was the caller's. A
--     member banned, kicked or on a deleted server could rewrite every DM
--     they had ever sent, and each edit rang its recipient. An edit is now a
--     member's, as every other DM write already was.
--   * The `avatars` bucket asked only that a member wrote under their own
--     id, and let anyone signed in read it. Sign-up is open, so a stranger
--     with no invite could upload 16 pictures a sign-in, and list and fetch
--     every member's picture on every server of the project. Writing now
--     takes a member, and reading takes a member of the same server.
--
-- A bot's grants are kept through a ban, so lifting it gives the reading
-- back as it was.

-- ── A bot's channels, while it is in ────────────────────────
CREATE OR REPLACE FUNCTION app.bot_channels() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(g.channel_id), '{}'::uuid[])
    FROM bot_channel_keys g
   WHERE g.bot_id = auth.uid()
     AND app.server_id() IS NOT NULL
$$;

COMMENT ON FUNCTION app.bot_channels() IS
  'The channels this bot holds a key for, as one array. Empty for a person, '
  'and for a bot banned or on a server being deleted.';

-- ── Who hears a channel ─────────────────────────────────────
-- The 002 body, with a banned bot left out of the bots told one at a time.
CREATE OR REPLACE FUNCTION app.announce_to_channel(
  p_channel UUID, p_event TEXT, p_payload JSONB)
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID;
  v_private BOOLEAN;
BEGIN
  SELECT c.server_id, c.is_private INTO v_server, v_private
    FROM channels c WHERE c.id = p_channel;
  IF v_server IS NULL THEN
    RETURN;
  END IF;

  -- One row either way. An open channel reaches the whole server, a private
  -- one reaches its own topic, and Realtime does the fanning out.
  IF v_private THEN
    PERFORM realtime.send(p_payload, p_event, 'channel:' || p_channel, true);
  ELSE
    PERFORM realtime.send(p_payload, p_event, 'server:' || v_server, true);
  END IF;

  -- A bot joins neither topic above; it hears everything on its own
  -- (BOTS.md §5), so it is told one at a time. A banned one still listens
  -- there, as a banned member does, to hear the ban lifted, so it is left
  -- out here rather than at the topic.
  PERFORM realtime.send(p_payload, p_event, 'user:' || g.bot_id, true)
     FROM bot_channel_keys g
     JOIN users u ON u.id = g.bot_id
    WHERE g.channel_id = p_channel AND NOT u.is_banned;
END $$;

-- ── A DM edited, by a member ────────────────────────────────
DROP POLICY IF EXISTS dm_messages_update_own ON dm_messages;
CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid() AND (SELECT app.server_id()) IS NOT NULL)
  WITH CHECK (sender_id = auth.uid() AND (SELECT app.server_id()) IS NOT NULL
              AND NOT app.timed_out() AND NOT app.blocked_by(recipient_id));

-- ── Avatars, among members ──────────────────────────────────
-- The folder is the member's id (`avatars_insert`); one that is not an id
-- is nobody's.
CREATE OR REPLACE FUNCTION app.avatar_owner(p_name TEXT) RETURNS UUID
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN f ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
              THEN f::uuid END
    FROM (SELECT (storage.foldername(p_name))[1] AS f) x
$$;

COMMENT ON FUNCTION app.avatar_owner(TEXT) IS
  'Whose avatar an object in the avatars bucket is: its folder, when that is an id.';

DROP POLICY IF EXISTS avatars_select ON storage.objects;
CREATE POLICY avatars_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'avatars'
         AND EXISTS (SELECT 1 FROM users u
                      WHERE u.id = app.avatar_owner(name)
                        AND u.server_id = (SELECT app.server_id())));

DROP POLICY IF EXISTS avatars_insert ON storage.objects;
CREATE POLICY avatars_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'avatars'
              AND (storage.foldername(name))[1] = auth.uid()::text
              AND (SELECT app.server_id()) IS NOT NULL);

DROP POLICY IF EXISTS avatars_update ON storage.objects;
CREATE POLICY avatars_update ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'avatars'
         AND (storage.foldername(name))[1] = auth.uid()::text
         AND (SELECT app.server_id()) IS NOT NULL);

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.avatar_owner(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.avatar_owner(TEXT) TO authenticated;
