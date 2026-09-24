-- ============================================================
-- Rift self-hosted server — 007: scheduled work
-- ============================================================
-- Everything that runs on a clock rather than in response to a request:
-- retention sweeps, expiring invites and summons, and clearing out
-- attachments whose message is gone.
-- ============================================================

-- ============================================================
-- Scheduled cleanup
-- ============================================================
-- One job. There used to be four: two swept the auth-challenge and token tables
-- that GoTrue replaced, and one pruned `notifications` — a table that existed
-- only to be counted and therefore only to be cleaned up. Read cursors don't
-- accumulate, so nothing prunes them.
--
-- Messages are never swept here. A self-hosted server is somebody's own
-- hardware and their own retention policy; deleting their history on a timer is
-- the central tier's bargain, not this one's.

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.unschedule('cleanup-expired-invites')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-invites');

SELECT cron.schedule(
  'cleanup-expired-invites',
  '0 * * * *',
  $$DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < now()$$
);

SELECT cron.unschedule('rift-message-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-message-retention');

SELECT cron.schedule(
  'rift-message-retention',
  '23 4 * * *',
  $$SELECT app.enforce_retention()$$
);

-- ============================================================
-- Every bucket, not only the attachments
-- ============================================================
-- This used to read `bucket_id LIKE 'chat-%'` and was named for it, and the
-- two buckets it left out both leak by design:
--
--   * **avatars.** A new picture is written to a fresh random path and the old
--     object is deliberately left behind, because somebody may still be drawing
--     it from cache (`server_profile_api.dart`). Nothing ever came back for it,
--     so every avatar anybody had ever set stayed on the disk forever — and
--     since `avatars_insert` only requires the folder to be the caller's own
--     id, a modified client could write under it in a loop. That bucket is not
--     matched by `app.enforce_storage_cap` or `app.track_bucket_usage` either,
--     both of which also say `chat-%`, so the bytes were uncapped, uncounted
--     and uncollected at once. Measured: one member, 400 MB, nothing refused.
--
--   * **soundboard.** Removing a clip deletes its row and leaves its blob to
--     the Storage API, which is what the policy suite asserts. The 48-clip
--     ceiling counts rows, so deleting and re-adding walks past it a blob at a
--     time.
--
-- So the question stops being "is this a chat bucket" and becomes the one it
-- always meant: **does anything still point at this object.** Each bucket
-- answers it from whatever holds its references — a message's timestamp, a
-- `users.avatar_path`, a `soundboard_sounds.object_path` — and the grace
-- period covers all three for the same reason, because in every case the blob
-- is uploaded before the row that names it.
--
-- `avatars` is shared by every server on the project, unlike `chat-<id>`. That
-- is safe to sweep from any server's call because the test is project-wide:
-- an avatar is orphaned when *no* user row anywhere names it, which is not a
-- fact about who asked.

CREATE OR REPLACE FUNCTION app.orphaned_attachments(p_grace INTERVAL DEFAULT '1 hour')
  RETURNS TABLE (bucket TEXT, object_name TEXT)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH obj AS (
    -- The grace period is a safety rail, not a nicety: an attachment is
    -- uploaded *before* the message that references it is inserted, so without
    -- it a sweep landing in that window would delete a blob whose message is
    -- milliseconds away from existing.
    SELECT o.bucket_id, o.name, o.created_at,
           split_part(o.name, '/', 1) AS scope
      FROM storage.objects o
     WHERE o.bucket_id LIKE 'chat-%'
       AND o.created_at < now() - p_grace
  ),
  -- A channel scope is the channel id. 'infinity' for a channel with nothing
  -- left in it means every object under it is orphaned, which is correct.
  channel_marks AS (
    SELECT c.id::TEXT AS scope,
           COALESCE(MIN(m.created_at), 'infinity'::TIMESTAMPTZ) AS keep_from
      FROM channels c
      LEFT JOIN messages m ON m.channel_id = c.id
     GROUP BY c.id
  ),
  -- A DM scope is the client's conversation context with its colons swapped
  -- for underscores: `dm_<lower uuid>_<higher uuid>`. Canonical lowercase
  -- UUIDs order the same as text and as uuid, so LEAST/GREATEST reproduce the
  -- client's sort.
  dm_marks AS (
    SELECT 'dm_' || LEAST(d.sender_id, d.recipient_id)::TEXT
                 || '_' || GREATEST(d.sender_id, d.recipient_id)::TEXT AS scope,
           MIN(d.created_at) AS keep_from
      FROM dm_messages d
     GROUP BY 1
  ),
  marks AS (
    SELECT * FROM channel_marks
    UNION ALL
    SELECT * FROM dm_marks
  )
  SELECT obj.bucket_id, obj.name
    FROM obj
    LEFT JOIN marks ON marks.scope = obj.scope
   -- No scope at all: the channel was deleted, or a conversation has no
   -- messages left anywhere.
   WHERE marks.scope IS NULL
      -- The margin is the same grace, used a second time and for a sharper
      -- reason. An attachment is uploaded *before* the message that carries its
      -- key, so the blobs of the oldest surviving message are themselves older
      -- than the watermark. Comparing against a bare `keep_from` would delete
      -- the attachments of the very message it was trying to protect, on every
      -- single sweep, silently.
      OR obj.created_at < marks.keep_from - p_grace

  -- ---------- avatars ----------
  UNION ALL
  SELECT o.bucket_id, o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'avatars'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_path = o.name)

  -- ---------- soundboard ----------
  UNION ALL
  SELECT o.bucket_id, o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'soundboard'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM soundboard_sounds s WHERE s.object_path = o.name);
$$;

CREATE OR REPLACE FUNCTION sweep_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_orphans JSONB;
BEGIN
  PERFORM app.enforce_retention();

  SELECT COALESCE(
           jsonb_agg(jsonb_build_object('bucket', bucket, 'name', object_name)),
           '[]'::JSONB)
    INTO v_orphans
    FROM (
      SELECT bucket, object_name FROM app.orphaned_attachments()
       ORDER BY bucket, object_name
       LIMIT GREATEST(p_limit, 0)
    ) capped;

  RETURN jsonb_build_object('orphans', v_orphans);
END; $$;

-- ============================================================
-- Retention, with the DM half now overridable
-- ============================================================
-- All four blocks read the same way: COALESCE the per-scope override onto the
-- server-wide number, so NULL inherits it and 0 opts out of it.

CREATE OR REPLACE FUNCTION app.enforce_retention() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ---------- channel messages, by age ----------
  -- COALESCE is the inherit rule: the channel's number when it set one, the
  -- server's when it didn't.
  DELETE FROM messages m
   USING channels c, servers s
   WHERE m.channel_id = c.id
     AND c.server_id  = s.id
     AND COALESCE(c.retention_days, s.message_retention_days) > 0
     AND m.created_at < now() - make_interval(
           days => COALESCE(c.retention_days, s.message_retention_days));

  -- ---------- DM messages, by age ----------
  -- A DM's server is its sender's; the CHECK on `dm_messages` and
  -- `can_receive_dm` both keep a pair inside one server, so either end answers.
  -- There is no per-conversation override to consult, but there is now a
  -- per-server DM one, and it reads exactly like a channel's.
  DELETE FROM dm_messages d
   USING users u, servers s
   WHERE d.sender_id  = u.id
     AND u.server_id  = s.id
     AND COALESCE(s.dm_retention_days, s.message_retention_days) > 0
     AND d.created_at < now() - make_interval(
           days => COALESCE(s.dm_retention_days, s.message_retention_days));

  -- ---------- channel messages, by count ----------
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id ORDER BY m.id DESC) AS rn,
             COALESCE(c.history_cap, s.message_history_cap) AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );

  -- ---------- DM messages, by count ----------
  -- Order-independent pair, matching `idx_dm_messages_pair` and central's
  -- equivalent sweep: a conversation is one bucket seen from either side, and
  -- the cap counts both people's messages together.
  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT d.id,
             row_number() OVER (
               PARTITION BY LEAST(d.sender_id, d.recipient_id),
                            GREATEST(d.sender_id, d.recipient_id)
               ORDER BY d.id DESC
             ) AS rn,
             COALESCE(s.dm_history_cap, s.message_history_cap) AS cap
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE COALESCE(s.dm_history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );
END; $$;

-- ---------- forgetting a device ----------
-- FCM tells the sender when a token is dead, but the sender here is central,
-- relaying for a database it holds no credentials for — and having it report
-- back which of a server's tokens had died would tell it which members had
-- uninstalled the app. So this side sweeps on staleness instead: the client
-- re-registers on every sign-in, so a row that has not been touched in two
-- months belongs to a device that has not opened Rift in two months.

SELECT cron.unschedule('cleanup-stale-device-tokens')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-stale-device-tokens');

SELECT cron.schedule(
  'cleanup-stale-device-tokens',
  '30 4 * * *',
  $$DELETE FROM device_tokens WHERE updated_at < now() - interval '60 days'$$
);

-- ============================================================
-- 2. And so does an hour of nobody using it
-- ============================================================

CREATE OR REPLACE FUNCTION app.expire_bot_voice_summons() RETURNS VOID
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM bot_voice_summons WHERE summoned_at < now() - interval '1 hour'
$$;

SELECT cron.unschedule('expire-bot-voice-summons')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'expire-bot-voice-summons');

SELECT cron.schedule(
  'expire-bot-voice-summons',
  '0 * * * *',
  $$SELECT app.expire_bot_voice_summons()$$
);
