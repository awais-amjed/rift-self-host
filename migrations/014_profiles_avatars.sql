-- Migration 014: editable profiles — display name + avatar.
--
-- display_name already exists (001) but had no self-service way to change it;
-- this adds the avatar half and the `avatars` bucket the bytes live in.
--
-- **Avatars are NOT E2E.** The server stores the image in the clear, the same
-- accepted trade-off as reactions (ARCHITECTURE.md §4): an avatar has to be
-- renderable by every member, and per-member wrapping of a picture that
-- everyone sees anyway buys nothing. Message content, attachments and DMs are
-- unaffected — they stay end-to-end encrypted.
--
-- The bucket is **private**, not public-read: an avatar fetchable by anyone who
-- learns the URL would leak faces to the unauthenticated internet, which sits
-- badly next to the rest of this app. Members read it with their own token.
--
-- avatar_path is the object name inside the bucket (`<user_id>/<random>.img`),
-- not a URL, so the bucket can move without rewriting rows. NULL = no avatar,
-- render initials.

ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_path TEXT;

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('avatars', 'avatars', false, 2097152)  -- 2 MB, downscaled client-side
ON CONFLICT (id) DO UPDATE SET file_size_limit = EXCLUDED.file_size_limit;

-- Everyone authenticated on this server may read any avatar (they are shown
-- next to every message); you may only write inside your own folder.
DROP POLICY IF EXISTS "avatars_select" ON storage.objects;
CREATE POLICY "avatars_select" ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'avatars');

DROP POLICY IF EXISTS "avatars_insert" ON storage.objects;
CREATE POLICY "avatars_insert" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

DROP POLICY IF EXISTS "avatars_update" ON storage.objects;
CREATE POLICY "avatars_update" ON storage.objects FOR UPDATE TO authenticated
  USING (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );

DROP POLICY IF EXISTS "avatars_delete" ON storage.objects;
CREATE POLICY "avatars_delete" ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = auth.uid()::text
  );
