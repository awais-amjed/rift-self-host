-- ============================================================
-- Rift self-hosted server — 006: buckets and the disk
-- ============================================================
-- Three buckets, their policies, and the cap that stops a server filling the
-- operator's disk.
--
-- The cap is a `BEFORE INSERT` trigger on `storage.objects` against a
-- running total, never a `SUM`. There is exactly one way for bytes to arrive
-- — an INSERT into that table — so the REST API, the attachment sweep, a
-- moderator deleting a message and a service-role script all go through the
-- same accounting. There is no fourth way in.
-- ============================================================

-- ============================================================
-- Storage
-- ============================================================
-- Two private buckets. Both are reachable by any authenticated member and rely
-- on different things for their safety, which is worth being explicit about:
--
--   chat-attachments  the bytes are AES-256-GCM ciphertext under a per-file key
--                     that only ever exists inside an encrypted message body.
--                     Reading an object gains you nothing without the message,
--                     and object names are random.
--   avatars           NOT encrypted. A picture every member renders gains
--                     nothing from per-member wrapping, so this is the same
--                     accepted trade-off as reactions. Private rather than
--                     public-read so it isn't fetchable by the open internet.

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('chat-attachments', 'chat-attachments', false, 26214400)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 26214400;

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('avatars', 'avatars', false, 2097152)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 2097152;

-- Soundboard clips. Unencrypted for the same reason avatars are — a clip every
-- member plays gains nothing from per-member wrapping — and private for the
-- same reason too. 5 MB each, which is the only ceiling on a clip that a
-- modified client cannot talk its way past.
--
-- 5 MB is the 30-second ceiling written as bytes: half a minute of WAV at
-- 44.1 kHz/16-bit stereo is about 5.3 MB, and `wav` is one of the formats
-- every target can decode. Anything compressed is far under it, so the size
-- cap only ever catches a file that was not going to be a clip.
--
-- Note what this number is doing, because nothing else is doing it: unlike
-- `chat-*`, this bucket is **not** counted by `app.track_bucket_usage` and
-- not refused by `app.enforce_storage_cap`, both of which match on
-- `bucket_id LIKE 'chat-%'`. So the per-file limit times
-- `app.soundboard_max()` — 48 × 5 MB, 240 MB — is the entire bound on what a
-- server's soundboard can cost its host. Raise either number and that is the
-- figure that moves.
--
-- Not `sound-<server uuid>`, unlike attachments: the two reasons a bucket per
-- server exists there are a per-server *size* cap and a read policy that can
-- name one server, and here the size cap is the same number for everybody
-- while the read policy has a folder to name instead.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('soundboard', 'soundboard', false, 5242880)
ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 5242880;

-- The server icon bucket predates the app's own uploads and stays public: it
-- is fetched before anyone has a session, on the join screen.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('servers', 'servers', true, 5242880)
ON CONFLICT (id) DO UPDATE SET public = true, file_size_limit = 5242880;

-- ============================================================
-- An attachment bucket per server
-- ============================================================
-- One Supabase project can host several servers, so each one gets its own
-- attachment bucket rather than sharing a project-wide one. Two things depend
-- on that:
--
--   * **The size cap can be exact.** `file_size_limit` is a property of a
--     bucket, so a shared bucket could only carry one number for every server
--     on it — the strictest server's cap would be client-enforced only, which
--     is a limit a modified client can ignore.
--   * **A member cannot read another server's blobs.** A shared bucket's read
--     policy can only say `bucket_id = 'chat-attachments'` for any
--     authenticated caller. The bytes are AES-256-GCM ciphertext so nothing
--     would leak, but every other rule here is scoped by `app.server_id()`
--     and this one would not be.
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

CREATE OR REPLACE FUNCTION sync_server_bucket() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM app.sync_server_bucket(NEW.id, NEW.max_attachment_bytes);
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION app.track_bucket_usage() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_old BIGINT := 0;
  v_new BIGINT := 0;
BEGIN
  -- The two sides are handled separately rather than as a delta, because an
  -- UPDATE can move an object between buckets as well as change its size.
  IF TG_OP IN ('UPDATE', 'DELETE') AND OLD.bucket_id LIKE 'chat-%' THEN
    v_old := COALESCE((OLD.metadata->>'size')::BIGINT, 0);
    UPDATE app.bucket_usage
       SET bytes = GREATEST(bytes - v_old, 0)
     WHERE bucket_id = OLD.bucket_id;
  END IF;

  IF TG_OP IN ('UPDATE', 'INSERT') AND NEW.bucket_id LIKE 'chat-%' THEN
    v_new := COALESCE((NEW.metadata->>'size')::BIGINT, 0);
    INSERT INTO app.bucket_usage (bucket_id, bytes)
    VALUES (NEW.bucket_id, v_new)
    ON CONFLICT (bucket_id)
      DO UPDATE SET bytes = app.bucket_usage.bytes + v_new;
  END IF;

  RETURN NULL;  -- AFTER trigger
END $$;

-- ============================================================
-- 3. Refusing the upload that would go over
-- ============================================================

CREATE OR REPLACE FUNCTION app.enforce_storage_cap() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_cap    BIGINT;
  v_used   BIGINT;
  v_size   BIGINT;
BEGIN
  -- Buckets are named `chat-<server id>`; anything else is not a server's
  -- attachments and is not this limit's business.
  IF NEW.bucket_id !~ '^chat-[0-9a-f-]{36}$' THEN
    RETURN NEW;
  END IF;
  v_server := substr(NEW.bucket_id, 6)::UUID;

  SELECT s.max_storage_bytes INTO v_cap FROM servers s WHERE s.id = v_server;
  IF COALESCE(v_cap, 0) = 0 THEN
    RETURN NEW;
  END IF;

  v_size := COALESCE((NEW.metadata->>'size')::BIGINT, 0);

  -- Locked, not just read. Two uploads landing together would otherwise both
  -- measure themselves against the same figure, both fit, and together not:
  -- 950 KB used under a 1 MB cap admits two 40 KB files and finishes at
  -- 1,030 KB. Demonstrated, not theorised.
  --
  -- The row has to exist before it can be locked, hence the insert — a bucket
  -- nobody has uploaded to yet has no row, and `FOR UPDATE` over nothing locks
  -- nothing.
  --
  -- This costs no contention. `app.track_bucket_usage` below already takes the
  -- same exclusive row lock, on the same row, and holds it to commit — so
  -- uploads to one server already serialise here. All this does is take that
  -- lock a few statements earlier, where the answer is still worth something.
  INSERT INTO app.bucket_usage (bucket_id, bytes) VALUES (NEW.bucket_id, 0)
    ON CONFLICT (bucket_id) DO NOTHING;
  SELECT COALESCE(u.bytes, 0) INTO v_used
    FROM app.bucket_usage u WHERE u.bucket_id = NEW.bucket_id FOR UPDATE;

  IF COALESCE(v_used, 0) + v_size > v_cap THEN
    -- A named condition rather than a bare string: Storage passes the
    -- message through to the client, and the uploader deserves a sentence
    -- rather than a constraint name.
    RAISE EXCEPTION
      'This server has no room left for attachments (% of % bytes used)',
      v_used, v_cap
      USING ERRCODE = 'disk_full';
  END IF;

  RETURN NEW;
END $$;

DROP POLICY IF EXISTS avatars_select ON storage.objects;
CREATE POLICY avatars_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'avatars');

DROP POLICY IF EXISTS avatars_insert ON storage.objects;
CREATE POLICY avatars_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

DROP POLICY IF EXISTS avatars_update ON storage.objects;
CREATE POLICY avatars_update ON storage.objects FOR UPDATE TO authenticated
  USING (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

DROP POLICY IF EXISTS avatars_delete ON storage.objects;
CREATE POLICY avatars_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

-- A clip lives under its server's id, which is the whole read rule: a member
-- of one server cannot fetch another's, even on a project hosting several.
-- Writing needs the bit, and the folder has to be the caller's own server —
-- without the second half, MANAGE_SOUNDBOARD on any server on the project
-- would be MANAGE_SOUNDBOARD on all of them.
DROP POLICY IF EXISTS soundboard_select ON storage.objects;
CREATE POLICY soundboard_select ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'soundboard'
    AND (storage.foldername(name))[1] = app.server_id()::text
  );

DROP POLICY IF EXISTS soundboard_insert ON storage.objects;
CREATE POLICY soundboard_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'soundboard'
    AND (storage.foldername(name))[1] = app.server_id()::text
    AND app.has_perm('MANAGE_SOUNDBOARD')
  );

-- No update policy at all. A path is minted once and never written twice —
-- replacing a clip's bytes under a name every client has cached is how you
-- get a picker where the labels and the sounds disagree.
DROP POLICY IF EXISTS soundboard_delete ON storage.objects;
CREATE POLICY soundboard_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'soundboard'
    AND (storage.foldername(name))[1] = app.server_id()::text
    AND app.has_perm('MANAGE_SOUNDBOARD')
  );

DROP POLICY IF EXISTS chat_attachments_select ON storage.objects;
CREATE POLICY chat_attachments_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'chat-' || app.server_id()::TEXT);

DROP POLICY IF EXISTS chat_attachments_insert ON storage.objects;
CREATE POLICY chat_attachments_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'chat-' || app.server_id()::TEXT);

DROP POLICY IF EXISTS chat_attachments_delete ON storage.objects;
CREATE POLICY chat_attachments_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND (owner = auth.uid() OR app.can_manage_channels())
  );

DROP TRIGGER IF EXISTS servers_bucket_insert ON servers;
CREATE TRIGGER servers_bucket_insert AFTER INSERT ON servers
  FOR EACH ROW EXECUTE FUNCTION sync_server_bucket();

DROP TRIGGER IF EXISTS servers_bucket_update ON servers;
CREATE TRIGGER servers_bucket_update AFTER UPDATE OF max_attachment_bytes ON servers
  FOR EACH ROW WHEN (OLD.max_attachment_bytes IS DISTINCT FROM NEW.max_attachment_bytes)
  EXECUTE FUNCTION sync_server_bucket();

DROP TRIGGER IF EXISTS rift_track_bucket_usage ON storage.objects;
CREATE TRIGGER rift_track_bucket_usage
  AFTER INSERT OR UPDATE OR DELETE ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION app.track_bucket_usage();

DROP TRIGGER IF EXISTS rift_enforce_storage_cap ON storage.objects;
CREATE TRIGGER rift_enforce_storage_cap
  BEFORE INSERT ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION app.enforce_storage_cap();
