-- ============================================================
-- Rift self-hosted server — 021: a server's own icon
-- ============================================================
-- `servers.icon_url` and the public `servers` bucket were both here from the
-- start, and nothing could put a picture in either: the bucket had no write
-- policy, so no member's token could upload to it, and the app had no way to
-- choose one. A server was always its initial.
--
-- Now an admin uploads the icon to `servers/<server id>/…`, and
-- `update_server` stores that **object path** in `icon_url`. It no longer
-- accepts an address: a column every member's app fetches from must not name
-- somebody else's host, or an admin could point it at one that logs who
-- opened the app and when. The app reads the path from this server's own
-- Storage, and the directory copies the bytes to central when the server is
-- listed, so a browser never fetches from here at all.
--
-- The bucket stays public, as 006 left it: the screen that opens an invite
-- draws the icon before the person opening it has a session.
--
-- Being public is also why it gains a type and a smaller size here. Whatever
-- is in it is served from the operator's own domain to anybody, with the
-- content type it was uploaded under, so a bucket that took any type would
-- let an admin of one server host a page on the domain of a project shared
-- with others. The app sends a 256-pixel PNG (`AvatarImage.prepare`), far
-- under the 2 MB an avatar is allowed.
--
-- And like every other bucket it is bounded and swept (006, 007): a few
-- objects per server, and an icon no `servers` row names is collected with
-- the rest. `app.orphaned_attachments` is replaced whole, as 007 left it
-- plus the block for this bucket.
-- ============================================================

UPDATE storage.buckets
   SET file_size_limit = 2097152,
       allowed_mime_types = ARRAY['image/png']
 WHERE id = 'servers';

-- ============================================================
-- Who may write it
-- ============================================================
-- The folder is the caller's own server, as for the soundboard, and only an
-- admin of it writes: the same rule `update_server` asks before it stores the
-- path. Without the folder half, an admin of any server on the project could
-- replace another's icon.
--
-- A select policy for the folder too, although the public endpoint ignores
-- it: Storage reads the row back after an upload, as the caller.
DROP POLICY IF EXISTS server_icons_select ON storage.objects;
CREATE POLICY server_icons_select ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'servers'
    AND (storage.foldername(name))[1] = app.server_id()::text
  );

DROP POLICY IF EXISTS server_icons_insert ON storage.objects;
CREATE POLICY server_icons_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'servers'
    AND (storage.foldername(name))[1] = app.server_id()::text
    AND app.is_admin()
  );

-- No update policy, for the soundboard's reason: a path is minted once, and
-- new bytes under a path every client has cached would never be drawn.
DROP POLICY IF EXISTS server_icons_delete ON storage.objects;
CREATE POLICY server_icons_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'servers'
    AND (storage.foldername(name))[1] = app.server_id()::text
    AND app.is_admin()
  );

-- ============================================================
-- How many it may hold
-- ============================================================
-- The sweep runs on a clock, and between two runs an admin's modified client
-- could otherwise upload in a loop. Eight is a day of changing your mind.
CREATE OR REPLACE FUNCTION app.server_icons_per_server() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 8 $$;

-- Its own trigger rather than a branch in `app.enforce_storage_cap`, which
-- would have to be replaced whole to learn a bucket it has no other use for.
-- The count is a prefix range on `name`, for the reason the avatar ceiling in
-- 006 gives: Storage's `(bucket_id, name COLLATE "C")` index answers it.
CREATE OR REPLACE FUNCTION app.enforce_server_icon_cap() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_folder TEXT;
BEGIN
  IF NEW.bucket_id <> 'servers' THEN
    RETURN NEW;
  END IF;
  v_folder := NULLIF(split_part(NEW.name, '/', 1), NEW.name);
  IF v_folder IS NOT NULL
     AND (SELECT count(*) FROM storage.objects o
           WHERE o.bucket_id = 'servers'
             AND o.name COLLATE "C" >= v_folder || '/'
             AND o.name COLLATE "C" <  v_folder || '0')
         >= app.server_icons_per_server() THEN
    RAISE EXCEPTION
      'Too many icons stored for this server — the old ones are cleared up shortly'
      USING ERRCODE = 'disk_full';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS rift_enforce_server_icon_cap ON storage.objects;
CREATE TRIGGER rift_enforce_server_icon_cap
  BEFORE INSERT ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION app.enforce_server_icon_cap();

-- ============================================================
-- What the sweep collects
-- ============================================================
-- As 007 left it, plus the last block. An icon is orphaned when no server on
-- the project names it, which, as for avatars, is not a fact about who asked.

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
     AND NOT EXISTS (SELECT 1 FROM soundboard_sounds s WHERE s.object_path = o.name)

  -- ---------- server icons ----------
  UNION ALL
  SELECT o.bucket_id, o.name
    FROM storage.objects o
   WHERE o.bucket_id = 'servers'
     AND o.created_at < now() - p_grace
     AND NOT EXISTS (SELECT 1 FROM servers s WHERE s.icon_url = o.name);
$$;

-- An address stored before this file is not a path in the bucket, and the
-- app no longer draws one; nothing put one there but a hand-made call.
UPDATE servers SET icon_url = NULL WHERE icon_url LIKE '%://%';

REVOKE ALL ON FUNCTION app.server_icons_per_server() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.enforce_server_icon_cap() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;
