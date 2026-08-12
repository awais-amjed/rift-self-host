-- ============================================================
-- Rift self-hosted server — 008: an attachment bucket per server
-- ============================================================
-- One Supabase project can host several servers (001 says so, and identity is
-- derived per (host, server_id) precisely to allow it). Attachments were still
-- landing in a single project-wide `chat-attachments` bucket, and that one
-- decision cost two things:
--
--   * **The size cap could not be exact.** `file_size_limit` is a property of a
--     bucket, so a shared bucket can only carry one number. 007 mirrored the
--     MAX across servers onto it and accepted that a stricter server's cap was
--     client-enforced only — a limit a modified client could ignore.
--   * **Members could read another server's blobs.** `chat_attachments_select`
--     was `bucket_id = 'chat-attachments'` for *any* authenticated caller. The
--     bytes are AES-256-GCM ciphertext so nothing leaked, but every other rule
--     in this schema is scoped by `app.server_id()` and this one wasn't.
--
-- A bucket per server collapses both into one equality. `chat-<server uuid>` is
-- 41 characters against Storage's 100-character limit, the bucket carries that
-- server's own cap, and the read policy becomes
-- `bucket_id = 'chat-' || app.server_id()`.
--
-- The pleasant surprise is that none of this needs an endpoint. `storage.buckets`
-- is only protected against DELETE (`protect_buckets_delete`), so plain SQL can
-- create a bucket and change its limit — which means a trigger can keep every
-- bucket in step with its server's column, and `update_server` stops needing to
-- touch storage at all.

-- ============================================================
-- 1. The bucket, and keeping it in step
-- ============================================================

CREATE OR REPLACE FUNCTION app.sync_server_bucket(
  p_server UUID,
  p_limit  BIGINT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_bucket TEXT := 'chat-' || p_server::TEXT;
BEGIN
  INSERT INTO storage.buckets (id, name, public, file_size_limit)
       VALUES (v_bucket, v_bucket, false, p_limit)
  ON CONFLICT (id) DO UPDATE
          SET public = false, file_size_limit = EXCLUDED.file_size_limit;
END; $$;

REVOKE ALL ON FUNCTION app.sync_server_bucket(UUID, BIGINT)
  FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION sync_server_bucket() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM app.sync_server_bucket(NEW.id, NEW.max_attachment_bytes);
  RETURN NEW;
END; $$;

-- A new server gets its bucket the moment its row exists, so `create_server`
-- needs no extra step and can't half-succeed.
DROP TRIGGER IF EXISTS servers_bucket_insert ON servers;
CREATE TRIGGER servers_bucket_insert AFTER INSERT ON servers
  FOR EACH ROW EXECUTE FUNCTION sync_server_bucket();

-- And an admin changing the cap moves the bucket with it. This is what 007's
-- `mirrorAttachmentCap()` did from the edge function, in the one place that
-- cannot be skipped or raced — the same statement that changes the column.
DROP TRIGGER IF EXISTS servers_bucket_update ON servers;
CREATE TRIGGER servers_bucket_update AFTER UPDATE OF max_attachment_bytes ON servers
  FOR EACH ROW WHEN (OLD.max_attachment_bytes IS DISTINCT FROM NEW.max_attachment_bytes)
  EXECUTE FUNCTION sync_server_bucket();

-- Backfill: every server that already exists.
SELECT app.sync_server_bucket(s.id, s.max_attachment_bytes) FROM servers s;

-- ============================================================
-- 2. Who may touch which bucket
-- ============================================================
-- One equality per policy, and `app.server_id()` already returns null for a
-- banned member — so a ban takes their attachments with it, like everything
-- else built on that helper.
--
-- Note what is *not* here: a policy for the old shared `chat-attachments`
-- bucket. It keeps existing (Storage refuses a SQL DELETE on a bucket) but has
-- no policy at all, so nothing can read or write it. Anything left inside is
-- unreachable — acceptable because it is also undecryptable without the
-- messages that carried its keys, and because nothing is deployed. Its rows are
-- still swept by `orphaned_attachments` below, which spans every `chat-%`
-- bucket, so it drains rather than lingering forever.

DROP POLICY IF EXISTS chat_attachments_select ON storage.objects;
CREATE POLICY chat_attachments_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'chat-' || app.server_id()::TEXT);

DROP POLICY IF EXISTS chat_attachments_insert ON storage.objects;
CREATE POLICY chat_attachments_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'chat-' || app.server_id()::TEXT);

-- Your own uploads, or anyone's if you may delete their message.
DROP POLICY IF EXISTS chat_attachments_delete ON storage.objects;
CREATE POLICY chat_attachments_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND (owner = auth.uid() OR app.can_manage_channels())
  );

-- ============================================================
-- 3. The sweep, across buckets
-- ============================================================
-- Same reasoning as 007 — an object is named for the scope it was uploaded to,
-- and anything older than the oldest surviving message of that scope belonged
-- to a message that is gone — but the answer now has to say *which* bucket, so
-- the caller can delete from the right one.
--
-- `chat-%` rather than a join to `servers`, so a bucket whose server row has
-- been deleted still drains.

DROP FUNCTION IF EXISTS app.orphaned_attachments(INTERVAL);

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
      OR obj.created_at < marks.keep_from - p_grace;
$$;

REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;

-- Same door as 007, now answering with bucket + name so the edge function knows
-- where to send each delete. Still `public` because PostgREST cannot see `app`,
-- and still granted to `service_role` alone — that grant is the only thing
-- between a member and a history sweep.
DROP FUNCTION IF EXISTS sweep_attachments(INTEGER);

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

REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;
