-- Migration 013: message editing and deletion.
--
-- Editing overwrites the envelope in place (ciphertext/nonce/signature, and
-- key_version since a rotation may have happened since the original send) and
-- stamps edited_at. The server still never sees plaintext — an edit is just a
-- new sealed body over the same row, re-signed by the sender.
--
-- Deletion is a HARD delete. An E2E app should not keep a tombstone carrying
-- the original ciphertext: "deleted" must mean the bytes are gone, not hidden.
-- Clients drop the row when it stops coming back from the list functions.
-- Reactions cascade with the row (migration 012 already ON DELETE CASCADE).
--
-- Who may do what is enforced in the edge functions, not here (the service
-- role bypasses RLS): edit = sender only; delete = sender, or a channel
-- manager / server admin for channel messages. DMs are delete-for-self-and-
-- peer by either participant — a DM has exactly two readers, so there is no
-- moderator case.

ALTER TABLE messages    ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;
ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;
