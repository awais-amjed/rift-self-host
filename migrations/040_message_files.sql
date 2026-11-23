-- ============================================================
-- Rift self-hosted server — 040: a message names its own files
-- ============================================================
-- Found in the app's review of moderation, Nov 22 2026.
--
-- A message's files are named only inside its sealed body, so the server
-- could not tell which objects in `chat-<server>` were whose. Two things
-- followed from that:
--
--   * Deleting a message mid-conversation never freed its files. The sender's
--     app removed them when the sender deleted it, but a moderator's delete,
--     a retention pass or a delete from another app left them, and the sweep
--     (`app.orphaned_attachments`) only collects what is older than the oldest
--     message left in that channel or conversation: a deleted message's files
--     with anything older still around stayed for good. A report's Delete said
--     the files went with it; they did not.
--   * So that a moderator's app could remove them itself, `chat_attachments_
--     delete` let anyone who manages channels delete any file in the server,
--     in channels they cannot read as well. The app stopped doing that on
--     Nov 22, because the paths come from a body its sender wrote and could
--     name other people's files; the policy still allowed it.
--
-- Now a message carries the storage paths of its files in the clear
-- (`attachment_paths`), checked on insert: each must be an object the sender
-- uploaded to this server's bucket, under the folder of the conversation it is
-- sent in. Deleting the message, by anyone and by any route, puts those paths
-- in `attachment_trash`, and the sweep removes them once no other message
-- names them. The bucket's delete policy is the uploader's alone.
--
-- What this tells the server it did not already know: which of a sender's
-- uploads went with which message. It already saw each object's size, time,
-- uploader and conversation folder, and the message that followed it seconds
-- later; it still sees no name, type or byte of a file.
--
-- An app from before this sends no paths. Its messages' files are left to the
-- sweep as they always were, and its own delete still removes its own files.
-- ============================================================

-- ── The column ──────────────────────────────────────────────

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS attachment_paths TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE dm_messages
  ADD COLUMN IF NOT EXISTS attachment_paths TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN messages.attachment_paths IS
  'The storage paths of this message''s files (chat-<server> bucket), checked '
  'on insert to be its sender''s own uploads to this channel. Never updated. '
  'Freed by the sweep when the message is deleted (attachment_trash).';
COMMENT ON COLUMN dm_messages.attachment_paths IS
  'As messages.attachment_paths, under the conversation''s dm_<low>_<high> folder.';

-- What the sweep asks of a deleted message's file: does any other message
-- still name it. Only rows with files are indexed, and the sweep's query
-- repeats the predicate so the planner can use it.
CREATE INDEX IF NOT EXISTS idx_messages_attachment_paths ON messages
  USING gin (attachment_paths) WHERE cardinality(attachment_paths) > 0;
CREATE INDEX IF NOT EXISTS idx_dm_messages_attachment_paths ON dm_messages
  USING gin (attachment_paths) WHERE cardinality(attachment_paths) > 0;

-- ── Checked on insert ───────────────────────────────────────
-- The paths are the sender's word, and deleting the message frees them, so
-- one naming somebody else's file would have it removed. Each must be:
--   * in this server's bucket and uploaded by the caller (`owner`), and
--   * under the folder of this conversation: the channel's id, or
--     `dm_<low>_<high>` as the app uploads a DM's files.
-- Ten files a message, each with a poster, and a link card's picture make 21
-- at most from today's app; 64 leaves room without letting one row name a
-- whole bucket.

CREATE OR REPLACE FUNCTION app.check_attachment_paths() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_scope  TEXT;
  v_bucket TEXT;
  v_path   TEXT;
BEGIN
  NEW.attachment_paths := COALESCE(NEW.attachment_paths, '{}');
  -- The server writing a row itself (a webhook, a notice) is trusted with
  -- what it names, as `attest_message` trusts it with the rest.
  IF v_me IS NULL OR cardinality(NEW.attachment_paths) = 0 THEN
    RETURN NEW;
  END IF;
  IF cardinality(NEW.attachment_paths) > 64 THEN
    RAISE EXCEPTION 'too_many_attachments';
  END IF;

  IF TG_TABLE_NAME = 'messages' THEN
    v_scope := NEW.channel_id::TEXT;
  ELSE
    v_scope := 'dm_' || LEAST(v_me, NEW.recipient_id)::TEXT
                || '_' || GREATEST(v_me, NEW.recipient_id)::TEXT;
  END IF;
  v_bucket := 'chat-' || app.server_id()::TEXT;

  FOREACH v_path IN ARRAY NEW.attachment_paths LOOP
    IF v_path IS NULL
       OR split_part(v_path, '/', 1) <> v_scope
       OR NOT EXISTS (SELECT 1 FROM storage.objects o
                       WHERE o.bucket_id = v_bucket
                         AND o.name = v_path
                         AND o.owner = v_me) THEN
      RAISE EXCEPTION 'attachment_not_yours';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

COMMENT ON FUNCTION app.check_attachment_paths() IS
  'A message''s attachment_paths must be its sender''s own uploads to this '
  'server, under the conversation''s folder.';

-- After `attest_*` by name, though it reads auth.uid() rather than the
-- sender_id that trigger writes.
DROP TRIGGER IF EXISTS messages_attachments_check ON messages;
CREATE TRIGGER messages_attachments_check BEFORE INSERT ON messages
  FOR EACH ROW EXECUTE FUNCTION app.check_attachment_paths();

DROP TRIGGER IF EXISTS dm_messages_attachments_check ON dm_messages;
CREATE TRIGGER dm_messages_attachments_check BEFORE INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.check_attachment_paths();

-- ── Deleted with the message ────────────────────────────────
-- The database cannot delete an object (`storage.protect_delete()`), so a
-- deleted message's paths wait here for the sweep, which removes them through
-- the Storage API.

CREATE TABLE IF NOT EXISTS attachment_trash (
  bucket     TEXT        NOT NULL,
  name       TEXT        NOT NULL,
  trashed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (bucket, name)
);

COMMENT ON TABLE attachment_trash IS
  'Files of deleted messages, waiting for sweep_attachments to remove them '
  'once no other message names them.';

-- One statement at a time, since a retention pass deletes in bulk. The bucket
-- is the channel's server, or the DM sender's. A message deleted because its
-- channel or its sender was is not found here, and needs not be: the sweep
-- already collects every file of a channel or conversation that is gone.
CREATE OR REPLACE FUNCTION app.trash_message_files() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_TABLE_NAME = 'messages' THEN
    INSERT INTO attachment_trash (bucket, name)
    SELECT DISTINCT 'chat-' || c.server_id::TEXT, p.path
      FROM gone g
      JOIN channels c ON c.id = g.channel_id
     CROSS JOIN LATERAL unnest(g.attachment_paths) AS p(path)
     WHERE cardinality(g.attachment_paths) > 0
    ON CONFLICT DO NOTHING;
  ELSE
    INSERT INTO attachment_trash (bucket, name)
    SELECT DISTINCT 'chat-' || u.server_id::TEXT, p.path
      FROM gone g
      JOIN users u ON u.id = g.sender_id
     CROSS JOIN LATERAL unnest(g.attachment_paths) AS p(path)
     WHERE cardinality(g.attachment_paths) > 0
    ON CONFLICT DO NOTHING;
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS messages_trash_files ON messages;
CREATE TRIGGER messages_trash_files AFTER DELETE ON messages
  REFERENCING OLD TABLE AS gone
  FOR EACH STATEMENT EXECUTE FUNCTION app.trash_message_files();

DROP TRIGGER IF EXISTS dm_messages_trash_files ON dm_messages;
CREATE TRIGGER dm_messages_trash_files AFTER DELETE ON dm_messages
  REFERENCING OLD TABLE AS gone
  FOR EACH STATEMENT EXECUTE FUNCTION app.trash_message_files();

-- ── What the sweep collects ─────────────────────────────────
-- As 021 left it, plus the trash: a file still there that no message names.
-- No grace period for those — the message that named them existed and is
-- gone.

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

  -- ---------- deleted messages' files ----------
  -- UNION, not UNION ALL: a file can be both trashed and below the watermark.
  UNION
  SELECT t.bucket, t.name
    FROM attachment_trash t
   WHERE EXISTS (SELECT 1 FROM storage.objects o
                  WHERE o.bucket_id = t.bucket AND o.name = t.name)
     AND NOT EXISTS (SELECT 1 FROM messages m
                      WHERE cardinality(m.attachment_paths) > 0
                        AND m.attachment_paths @> ARRAY[t.name])
     AND NOT EXISTS (SELECT 1 FROM dm_messages d
                      WHERE cardinality(d.attachment_paths) > 0
                        AND d.attachment_paths @> ARRAY[t.name])

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

-- As 007 left it, after forgetting what the trash no longer needs: a file the
-- last sweep removed, or one another message still names (that message's own
-- delete puts it back).
CREATE OR REPLACE FUNCTION sweep_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_orphans JSONB;
BEGIN
  PERFORM app.enforce_retention();

  DELETE FROM attachment_trash t
   WHERE NOT EXISTS (SELECT 1 FROM storage.objects o
                      WHERE o.bucket_id = t.bucket AND o.name = t.name)
      OR EXISTS (SELECT 1 FROM messages m
                  WHERE cardinality(m.attachment_paths) > 0
                    AND m.attachment_paths @> ARRAY[t.name])
      OR EXISTS (SELECT 1 FROM dm_messages d
                  WHERE cardinality(d.attachment_paths) > 0
                    AND d.attachment_paths @> ARRAY[t.name]);

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

-- ── The bucket's delete: the uploader's alone ───────────────
-- A moderator's delete frees a message's files through the trash now, so
-- nobody needs to delete another member's file directly.
DROP POLICY IF EXISTS chat_attachments_delete ON storage.objects;
CREATE POLICY chat_attachments_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND owner = auth.uid()
  );

-- ── Grants ──────────────────────────────────────────────────
-- Sent with the message and never changed: no UPDATE grant.
GRANT INSERT (attachment_paths) ON messages TO authenticated;
GRANT INSERT (attachment_paths) ON dm_messages TO authenticated;

REVOKE ALL ON attachment_trash FROM PUBLIC, anon, authenticated;
ALTER TABLE attachment_trash ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON FUNCTION app.check_attachment_paths() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.trash_message_files() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;
