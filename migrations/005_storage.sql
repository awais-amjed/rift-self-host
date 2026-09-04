-- ============================================================
-- Rift self-hosted server — 005: storage
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

-- The server icon bucket predates the app's own uploads and stays public: it
-- is fetched before anyone has a session, on the join screen.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('servers', 'servers', true, 5242880)
ON CONFLICT (id) DO UPDATE SET public = true, file_size_limit = 5242880;

-- ---------- chat-attachments ----------

DROP POLICY IF EXISTS chat_attachments_select ON storage.objects;
CREATE POLICY chat_attachments_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'chat-attachments');

DROP POLICY IF EXISTS chat_attachments_insert ON storage.objects;
CREATE POLICY chat_attachments_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'chat-attachments');

-- ---------- avatars ----------
-- Own folder only, so a row can't be pointed at someone else's object and an
-- avatar can't be overwritten by another member.

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
