-- ============================================================
-- Rift self-hosted server — 048: the attachment sweep and the retention pass
-- look things up instead of reading everything
-- ============================================================
-- Found in the query review of Nov 25 2026, measured the same day on a test
-- database of 50,000 members, 320 channels, 5 million messages, 445,000 DMs
-- and 220,000 files.
--
-- Every member's app calls the attachment sweep as it opens a server (043
-- spaced the runs a minute apart). It did three costly things:
--
--   * It ran the retention pass first. With a 180-day age set that took 23 s,
--     with a history cap 31 s: past the API's 8-second limit, so the call
--     failed, the pass was undone, and on a server with retention on no file
--     was ever swept. The age pass had no index on `created_at` to start
--     from, and the history cap numbered every message of every channel
--     (`row_number()`) to find the ones past it.
--   * It found the oldest message of every channel and every conversation by
--     reading all of them (`MIN(created_at) ... GROUP BY`), and read every
--     file in every bucket: 1.6 s of the 2.2 s a sweep took with retention
--     off, every minute.
--
-- Now:
--
--   * The sweep does not run retention. The `rift-message-retention` job
--     does, every hour rather than once a day, since the sweep no longer
--     brings it round sooner.
--   * Retention by age reads only the old end of the table, through a BRIN
--     index on `created_at` (a few pages: rows are written in time order). By
--     count, it asks each capped channel and conversation for the row `cap`
--     back from its newest, a walk of its index, and deletes what is older.
--     Presses are counted on their own as before, now from an index of their
--     own (`idx_messages_presses`).
--   * The whole-bucket half of the sweep (files older than every message
--     left in their channel or conversation, avatars, sounds and icons
--     nobody names) runs once a day, until a pass finds nothing. It asks each
--     channel for its first message, and each conversation that has files for
--     its first, one index probe each. Deleted messages' files
--     (`attachment_trash`) are still swept on every call: those are the files
--     a member is waiting to see go.
--   * `app.announce_message` rings nobody for a message the retention pass
--     deletes, as `app.announce_dm` has not since 044: a pass deletes up to
--     500,000 rows of history nobody has open.
--
-- The oldest message of a channel is now its first by id rather than by
-- time. Ids are handed out as rows are written and `created_at` is pinned on
-- write (`app.attest_message`), so the two agree; the hour's margin the sweep
-- keeps would cover any that did not.
-- ============================================================

-- ── Indexes ─────────────────────────────────────────────────
-- A BRIN index is a few pages for millions of rows and builds in one read of
-- the table. Built here inside the migration's transaction, it holds writes
-- to the table for that read (about 2 s for 5 million messages).

CREATE INDEX IF NOT EXISTS idx_messages_created_brin ON messages
  USING brin (created_at);
CREATE INDEX IF NOT EXISTS idx_dm_messages_created_brin ON dm_messages
  USING brin (created_at);

-- Presses are few and never shown; the history cap counts them on their own.
CREATE INDEX IF NOT EXISTS idx_messages_presses ON messages (channel_id, id)
  WHERE is_interaction;

-- ── Retention ───────────────────────────────────────────────
-- What it deletes is unchanged from 044: by age, then by count, for channels
-- and DMs, and ended DM calls by age. Up to `p_limit` rows of each kind.

CREATE OR REPLACE FUNCTION app.enforce_retention(p_limit INTEGER DEFAULT 500000)
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_days INTEGER;
  v_left INTEGER;
  v_n    INTEGER;
  v_edge BIGINT;
  v_ch   RECORD;
  v_pair RECORD;
BEGIN
  PERFORM set_config('rift.retention', 'on', true);

  -- ---------- channel messages, by age ----------
  -- The shortest age anywhere bounds the read, so the BRIN index can be used;
  -- each row is then held to its own channel's age.
  SELECT min(COALESCE(c.retention_days, s.message_retention_days)) INTO v_days
    FROM channels c JOIN servers s ON s.id = c.server_id
   WHERE COALESCE(c.retention_days, s.message_retention_days) > 0;
  IF v_days IS NOT NULL THEN
    DELETE FROM messages WHERE id IN (
      SELECT m.id
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE m.created_at < now() - make_interval(days => v_days)
         AND COALESCE(c.retention_days, s.message_retention_days) > 0
         AND m.created_at < now() - make_interval(
               days => COALESCE(c.retention_days, s.message_retention_days))
       ORDER BY m.id
       LIMIT p_limit);
  END IF;

  -- ---------- DM messages, by age ----------
  SELECT min(COALESCE(s.dm_retention_days, s.message_retention_days)) INTO v_days
    FROM servers s
   WHERE COALESCE(s.dm_retention_days, s.message_retention_days) > 0;
  IF v_days IS NOT NULL THEN
    DELETE FROM dm_messages WHERE id IN (
      SELECT d.id
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE d.created_at < now() - make_interval(days => v_days)
         AND COALESCE(s.dm_retention_days, s.message_retention_days) > 0
         AND d.created_at < now() - make_interval(
               days => COALESCE(s.dm_retention_days, s.message_retention_days))
       ORDER BY d.id
       LIMIT p_limit);

    -- ---------- DM calls, by age ----------
    DELETE FROM dm_calls WHERE id IN (
      SELECT c.id
        FROM dm_calls c
        JOIN users   u ON u.id = c.caller_id
        JOIN servers s ON s.id = u.server_id
       WHERE COALESCE(s.dm_retention_days, s.message_retention_days) > 0
         AND c.ended_at IS NOT NULL
         AND c.started_at < now() - make_interval(
               days => COALESCE(s.dm_retention_days, s.message_retention_days))
       ORDER BY c.started_at
       LIMIT p_limit);
  END IF;

  -- ---------- channel messages, by count ----------
  -- The row `cap` back from the newest is the edge; it and everything older
  -- goes. A channel with fewer rows than the cap in all has nothing past it
  -- of either kind, and finding that out reads at most `cap` index entries.
  v_left := p_limit;
  FOR v_ch IN
    SELECT c.id, COALESCE(c.history_cap, s.message_history_cap) AS cap
      FROM channels c JOIN servers s ON s.id = c.server_id
     WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
     ORDER BY c.id
  LOOP
    EXIT WHEN v_left <= 0;

    v_edge := NULL;
    SELECT m.id INTO v_edge FROM messages m
     WHERE m.channel_id = v_ch.id
     ORDER BY m.id DESC OFFSET v_ch.cap LIMIT 1;
    CONTINUE WHEN v_edge IS NULL;

    -- Presses are ranked on their own: they are never shown, so they must
    -- not push out what is. Most channels have none, and then the edge just
    -- found is the edge of the rest. Skipping presses means reading each row,
    -- not only the index, so it is done only where there are some.
    IF EXISTS (SELECT 1 FROM messages m
                WHERE m.channel_id = v_ch.id AND m.is_interaction) THEN
      v_edge := NULL;
      SELECT m.id INTO v_edge FROM messages m
       WHERE m.channel_id = v_ch.id AND NOT m.is_interaction
       ORDER BY m.id DESC OFFSET v_ch.cap LIMIT 1;
    END IF;
    IF v_edge IS NOT NULL THEN
      DELETE FROM messages WHERE id IN (
        SELECT m.id FROM messages m
         WHERE m.channel_id = v_ch.id AND NOT m.is_interaction AND m.id <= v_edge
         ORDER BY m.id LIMIT v_left);
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_left := v_left - v_n;
    END IF;

    v_edge := NULL;
    SELECT m.id INTO v_edge FROM messages m
     WHERE m.channel_id = v_ch.id AND m.is_interaction
     ORDER BY m.id DESC OFFSET v_ch.cap LIMIT 1;
    IF v_edge IS NOT NULL AND v_left > 0 THEN
      DELETE FROM messages WHERE id IN (
        SELECT m.id FROM messages m
         WHERE m.channel_id = v_ch.id AND m.is_interaction AND m.id <= v_edge
         ORDER BY m.id LIMIT v_left);
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_left := v_left - v_n;
    END IF;
  END LOOP;

  -- ---------- DM messages, by count ----------
  -- Each conversation has a head row for at least one of its two people
  -- (`app.remember_dm_head`), so the heads name every conversation there is.
  v_left := p_limit;
  FOR v_pair IN
    SELECT DISTINCT LEAST(h.user_id, h.peer_id) AS low,
                    GREATEST(h.user_id, h.peer_id) AS high,
                    COALESCE(s.dm_history_cap, s.message_history_cap) AS cap
      FROM dm_conversation_heads h
      JOIN users   u ON u.id = h.user_id
      JOIN servers s ON s.id = u.server_id
     WHERE COALESCE(s.dm_history_cap, s.message_history_cap) > 0
     ORDER BY 1, 2
  LOOP
    EXIT WHEN v_left <= 0;

    v_edge := NULL;
    SELECT d.id INTO v_edge FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id) = v_pair.low
       AND GREATEST(d.sender_id, d.recipient_id) = v_pair.high
     ORDER BY d.id DESC OFFSET v_pair.cap LIMIT 1;
    CONTINUE WHEN v_edge IS NULL;

    DELETE FROM dm_messages WHERE id IN (
      SELECT d.id FROM dm_messages d
       WHERE LEAST(d.sender_id, d.recipient_id) = v_pair.low
         AND GREATEST(d.sender_id, d.recipient_id) = v_pair.high
         AND d.id <= v_edge
       ORDER BY d.id LIMIT v_left);
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_left := v_left - v_n;
  END LOOP;

  PERFORM set_config('rift.retention', '', true);
END; $$;

-- Every hour: the sweep no longer runs it on the way.
SELECT cron.unschedule('rift-message-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-message-retention');
SELECT cron.schedule(
  'rift-message-retention',
  '23 * * * *',
  $$SELECT app.enforce_retention()$$
);

-- ── A retention delete rings nobody ─────────────────────────
-- As in 023, silent for a delete made by the retention pass.

CREATE OR REPLACE FUNCTION app.announce_message() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row     messages%ROWTYPE;
  v_event   TEXT;
  v_payload JSONB;
  v_call    UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' AND current_setting('rift.retention', true) = 'on' THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    v_event := 'message';
    v_payload := jsonb_build_object(
      'id',           v_row.id,
      'channel_id',   v_row.channel_id,
      'sender_id',    v_row.sender_id,
      'mentions',     COALESCE(to_jsonb(v_row.mentions), '[]'::jsonb),
      'mentions_all', COALESCE(v_row.mentions_all, false));
  ELSE
    v_event := 'message_changed';
    v_payload := jsonb_build_object(
      'message_id', v_row.id,
      'channel_id', v_row.channel_id);
  END IF;

  -- Whoever it is for, and nobody else. An interaction with no bot to answer
  -- it is for nobody, and saying so to a topic called `user:` is worse than
  -- saying nothing.
  IF v_row.is_interaction OR v_row.ephemeral_for IS NOT NULL THEN
    IF COALESCE(v_row.ephemeral_for, v_row.to_bot) IS NOT NULL THEN
      PERFORM realtime.send(v_payload, v_event,
        'user:' || COALESCE(v_row.ephemeral_for, v_row.to_bot), true);
    END IF;
    RETURN NULL;
  END IF;

  PERFORM app.announce_to_channel(v_row.channel_id, v_event, v_payload);
  IF v_row.to_bot IS NOT NULL THEN
    PERFORM realtime.send(v_payload, v_event, 'user:' || v_row.to_bot, true);
  END IF;

  v_call := app.panel_call(v_row.blocks);
  IF v_call IS NULL AND TG_OP = 'UPDATE' THEN
    v_call := app.panel_call(OLD.blocks);
  END IF;
  IF v_call IS NOT NULL
     AND EXISTS (SELECT 1 FROM channels c
                  WHERE c.id IN (v_call, v_row.channel_id) AND c.is_private) THEN
    PERFORM app.announce_to_channel(v_call, v_event, v_payload);
  END IF;
  RETURN NULL;
END $$;

-- ── What the sweep collects ─────────────────────────────────
-- Deleted messages' files that are still there and that no other message
-- names, as in 040. No grace period: the message that named them existed and
-- is gone.

CREATE OR REPLACE FUNCTION app.trashed_attachments()
  RETURNS TABLE (bucket TEXT, object_name TEXT)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT t.bucket, t.name
    FROM attachment_trash t
   WHERE EXISTS (SELECT 1 FROM storage.objects o
                  WHERE o.bucket_id = t.bucket AND o.name = t.name)
     AND NOT EXISTS (SELECT 1 FROM messages m
                      WHERE cardinality(m.attachment_paths) > 0
                        AND m.attachment_paths @> ARRAY[t.name])
     AND NOT EXISTS (SELECT 1 FROM dm_messages d
                      WHERE cardinality(d.attachment_paths) > 0
                        AND d.attachment_paths @> ARRAY[t.name]);
$$;

-- Everything, as 040 left it, with each scope's oldest message found by one
-- index probe.
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
           COALESCE((SELECT m.created_at FROM messages m
                      WHERE m.channel_id = c.id
                      ORDER BY m.id LIMIT 1),
                    'infinity'::TIMESTAMPTZ) AS keep_from
      FROM channels c
  ),
  -- A DM scope is the client's conversation context with its colons swapped
  -- for underscores: `dm_<lower uuid>_<higher uuid>`. Canonical lowercase
  -- UUIDs order the same as text and as uuid, so LEAST/GREATEST reproduce the
  -- client's sort. Only the conversations that have files are asked, and one
  -- with no messages left has no mark, so its files go.
  dm_scopes AS (
    SELECT DISTINCT obj.scope FROM obj
     WHERE obj.scope ~ ('^dm_' || '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                        || '_' || '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
  ),
  dm_marks AS (
    SELECT * FROM (
      SELECT s.scope,
             (SELECT d.created_at FROM dm_messages d
               WHERE LEAST(d.sender_id, d.recipient_id) = split_part(s.scope, '_', 2)::UUID
                 AND GREATEST(d.sender_id, d.recipient_id) = split_part(s.scope, '_', 3)::UUID
               ORDER BY d.id LIMIT 1) AS keep_from
        FROM dm_scopes s
    ) first_messages
     WHERE keep_from IS NOT NULL
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

  -- ---------- deleted messages' files ----------
  -- UNION, not UNION ALL: a file can be both trashed and below the watermark.
  UNION
  SELECT * FROM app.trashed_attachments()

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
     AND NOT EXISTS (SELECT 1 FROM soundboard_sounds s WHERE s.object_path = o.name)

  -- ---------- server icons ----------
  UNION ALL
  SELECT o.bucket_id, o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'servers'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM servers s WHERE s.icon_url = o.name);
$$;

-- ── The sweep ───────────────────────────────────────────────
-- When the last whole pass found nothing. Until a day after that, a sweep
-- collects only deleted messages' files.

ALTER TABLE app.attachment_sweep_runs ADD COLUMN IF NOT EXISTS whole_at TIMESTAMPTZ;

COMMENT ON COLUMN app.attachment_sweep_runs.whole_at IS
  'When a whole pass of the sweep (app.orphaned_attachments) last found nothing. '
  'The next whole pass is a day later; the sweeps between collect only '
  'deleted messages'' files.';

-- As 040 left it, without the retention pass, and with the whole pass once a
-- day.
CREATE OR REPLACE FUNCTION sweep_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_orphans JSONB;
  v_whole   BOOLEAN;
BEGIN
  -- Forget what the trash no longer needs: a file the last sweep removed, or
  -- one another message still names (that message's own delete puts it back).
  DELETE FROM attachment_trash t
   WHERE NOT EXISTS (SELECT 1 FROM storage.objects o
                      WHERE o.bucket_id = t.bucket AND o.name = t.name)
      OR EXISTS (SELECT 1 FROM messages m
                  WHERE cardinality(m.attachment_paths) > 0
                    AND m.attachment_paths @> ARRAY[t.name])
      OR EXISTS (SELECT 1 FROM dm_messages d
                  WHERE cardinality(d.attachment_paths) > 0
                    AND d.attachment_paths @> ARRAY[t.name]);

  v_whole := NOT EXISTS (SELECT 1 FROM app.attachment_sweep_runs r
                          WHERE r.whole_at > now() - interval '1 day');

  IF v_whole THEN
    SELECT COALESCE(
             jsonb_agg(jsonb_build_object('bucket', bucket, 'name', object_name)),
             '[]'::JSONB)
      INTO v_orphans
      FROM (
        SELECT bucket, object_name FROM app.orphaned_attachments()
         ORDER BY bucket, object_name
         LIMIT GREATEST(p_limit, 0)
      ) capped;

    -- A pass that found something runs again next time, after the edge
    -- function has removed what it found, until one finds nothing.
    IF jsonb_array_length(v_orphans) = 0 THEN
      INSERT INTO app.attachment_sweep_runs (id, last_at, whole_at)
      VALUES (true, now(), now())
      ON CONFLICT (id) DO UPDATE SET whole_at = now();
    END IF;
  ELSE
    SELECT COALESCE(
             jsonb_agg(jsonb_build_object('bucket', bucket, 'name', object_name)),
             '[]'::JSONB)
      INTO v_orphans
      FROM (
        SELECT bucket, object_name FROM app.trashed_attachments()
         ORDER BY bucket, object_name
         LIMIT GREATEST(p_limit, 0)
      ) capped;
  END IF;

  RETURN jsonb_build_object('orphans', v_orphans);
END; $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.enforce_retention(INTEGER) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_message() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.trashed_attachments() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;
