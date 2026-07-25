-- Migration 011: Storage bucket for E2E-encrypted chat attachments.
--
-- Rich messages (images, voice notes, files) reference attachment *blobs* that
-- are AES-256-GCM-encrypted on the client before upload. The per-file key never
-- leaves the device except sealed inside the (already-encrypted) message body,
-- so the server only ever holds opaque ciphertext — it can neither decrypt a
-- blob nor even see its filename or mime type (those live in the message body
-- too, ARCHITECTURE.md §4).
--
-- Because the bytes are meaningless without a key that only channel/DM members
-- can obtain (by decrypting a message they're authorized to read), bucket
-- access is simply "authenticated": any signed-in member may upload and fetch.
-- Object *paths* are random and only discoverable by decrypting a message, so
-- read-for-authenticated leaks nothing. A hard per-file size cap bounds abuse.
--
-- Idempotent — safe to re-run.

-- Private bucket, 25 MB per object.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('chat-attachments', 'chat-attachments', false, 26214400)
ON CONFLICT (id) DO UPDATE
  SET public = EXCLUDED.public,
      file_size_limit = EXCLUDED.file_size_limit;

-- Any authenticated member can upload.
DROP POLICY IF EXISTS "chat_attachments_insert" ON storage.objects;
CREATE POLICY "chat_attachments_insert"
  ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'chat-attachments');

-- Any authenticated member can read (blobs are useless without the in-message
-- key; paths are unguessable).
DROP POLICY IF EXISTS "chat_attachments_select" ON storage.objects;
CREATE POLICY "chat_attachments_select"
  ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'chat-attachments');
