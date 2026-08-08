-- Migration 015: unread badges for server DMs.
--
-- Channel messages have had real unread counts since 007: `send_message` fans
-- out one `notifications` row per recipient, and the client counts the rows
-- with `read_at IS NULL`. DMs never did — the badge next to "Server DMs" was
-- a tally of open conversations, which never changed when a message arrived.
--
-- Rather than invent a second mechanism, a notification row now points at
-- *either* a channel message or a DM. Everything the channel path already
-- gives us comes along for free: counts survive a restart, read state is
-- server-side so it agrees across devices, RLS already scopes rows to
-- `auth.uid()`, the table is already in the Realtime publication, and the
-- retention job from 008 prunes DM rows on the same schedule.
--
-- A DM row carries the *peer* (the sender, since only inbound DMs are ever
-- unread) rather than a channel, because that is what the client badges: one
-- count per conversation.

ALTER TABLE notifications ALTER COLUMN channel_id DROP NOT NULL;
ALTER TABLE notifications ALTER COLUMN message_id DROP NOT NULL;

ALTER TABLE notifications
  ADD COLUMN IF NOT EXISTS dm_peer_id UUID REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE notifications
  ADD COLUMN IF NOT EXISTS dm_message_id BIGINT
    REFERENCES dm_messages(id) ON DELETE CASCADE;

-- Exactly one target, fully populated. Without this, dropping the NOT NULLs
-- above would let a row through that points at nothing.
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_one_target;
ALTER TABLE notifications ADD CONSTRAINT notifications_one_target CHECK (
  (
    channel_id IS NOT NULL AND message_id IS NOT NULL
    AND dm_peer_id IS NULL AND dm_message_id IS NULL
  )
  OR (
    dm_peer_id IS NOT NULL AND dm_message_id IS NOT NULL
    AND channel_id IS NULL AND message_id IS NULL
  )
);

-- Mirrors idx_notifications_user_unread for the per-conversation lookup: the
-- client both counts and clears by (user, peer).
CREATE INDEX IF NOT EXISTS idx_notifications_user_dm_unread
  ON notifications (user_id, dm_peer_id) WHERE read_at IS NULL;
