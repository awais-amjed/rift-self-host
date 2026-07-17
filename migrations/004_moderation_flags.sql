-- Migration 004: Persistent server-side moderation state.
--
-- is_muted / is_deafened are the source of truth for moderation, set by
-- channel managers / server admins via the moderate_user edge function.
-- They persist across sessions: get_channel_token mints LiveKit tokens
-- without microphone-publish permission while muted (and without subscribe
-- permission while deafened), so the state re-applies on every rejoin,
-- reconnect, and channel hop — and cannot be undone client-side.

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_muted    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deafened BOOLEAN NOT NULL DEFAULT false;
