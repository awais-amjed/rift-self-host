-- ============================================================
-- Rift self-hosted server — 016: a stored file is read where it was sent
-- ============================================================
-- `chat_attachments_select` let any member of a server read any object in its
-- bucket, and so list them all through Storage. That was written when every
-- file was ciphertext under a key that exists only inside a sealed message
-- body, and its header said so: reading an object gained nothing without the
-- message. Two things since have made it a leak:
--
--   * A big file can go up unencrypted (Oct 7). A member outside a server DM
--     or a private channel could list such a file there and download it,
--     where the composer had told its sender only that the server could see
--     it.
--   * Even sealed, a file's size and the time it was sent are something a
--     member outside the conversation had no business reading.
--
-- So an object is now read only by whoever may read the conversation it was
-- sent in. The client names every object for one — a channel's id, or
-- `dm_<a>_<b>` for a server DM, the two member ids in sorted order — as the
-- first part of its path, and the policy asks that conversation's own
-- question: `app.can_see_channel` for a channel, being one of the two for a
-- DM. Whoever uploaded an object reads it whatever its name, which is also
-- what Storage needs to hand an upload back.
--
-- Nothing else reads the bucket as a member. The orphan sweep and the storage
-- cap run as the database's owner, and a client deletes only blobs of
-- messages it can see.
-- ============================================================

CREATE OR REPLACE FUNCTION app.can_read_attachment(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_scope TEXT := split_part(p_name, '/', 1);
  v_me    TEXT := auth.uid()::TEXT;
BEGIN
  IF v_scope ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN app.can_see_channel(v_scope::UUID);
  END IF;
  -- `dm_` and two ids of 36 characters with `_` between: the first starts at
  -- the fourth character, the second at the forty-first.
  IF v_scope ~ '^dm_[0-9a-f-]{36}_[0-9a-f-]{36}$' THEN
    RETURN v_me IS NOT NULL
       AND v_me IN (substr(v_scope, 4, 36), substr(v_scope, 41, 36));
  END IF;
  RETURN false;
END $$;

COMMENT ON FUNCTION app.can_read_attachment(TEXT) IS
  'Whether the caller may read the chat attachment stored as p_name: one sent '
  'in a channel they can see, or in a server DM they are one end of.';

DROP POLICY IF EXISTS chat_attachments_select ON storage.objects;
CREATE POLICY chat_attachments_select ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND (owner = auth.uid() OR app.can_read_attachment(name))
  );

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.can_read_attachment(TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.can_read_attachment(TEXT) TO authenticated;
