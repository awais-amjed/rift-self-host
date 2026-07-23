-- Migration 007: Move to Supabase-native JWT auth (Sign-in-with-Web3 / SIWS).
--
-- Replaces the opaque per-server token model with GoTrue sessions. The client
-- authenticates by signing a SIWS message with its per-server Ed25519 key
-- (grant_type=web3); GoTrue issues the JWT. `public.users.id` becomes the
-- GoTrue `auth.users.id`, so RLS ownership is simply `auth.uid() = <col>` and
-- every existing FK (messages.sender_id, channel_keyring.user_id/wrapped_by,
-- dm_messages.*) carries the GoTrue uuid unchanged.
--
-- Assumes ONE server per Supabase instance (one GoTrue identity per host).
-- Apply on a reset test DB — this drops the legacy auth tables.
-- See auth.md for the full design.

-- ============================================================
-- 1. Drop the legacy opaque-token + challenge machinery
-- ============================================================
-- Sessions are now GoTrue JWTs; challenges are handled inside GoTrue's SIWS
-- flow. Key rotation is removed (seed-derived keys share the seed's fate).
DROP TABLE IF EXISTS tokens          CASCADE;
DROP TABLE IF EXISTS auth_challenges CASCADE;

SELECT cron.unschedule('cleanup-expired-tokens')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-tokens');
SELECT cron.unschedule('cleanup-expired-challenges')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-challenges');

-- ============================================================
-- 2. Bind users.id to the GoTrue identity
-- ============================================================
-- id is now supplied by register (= auth.uid()) and cascades from auth.users.
-- (Empty table on a reset DB, so the FK adds cleanly.)
ALTER TABLE users ALTER COLUMN id DROP DEFAULT;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_id_fkey;
ALTER TABLE users
  ADD CONSTRAINT users_id_fkey
  FOREIGN KEY (id) REFERENCES auth.users (id) ON DELETE CASCADE;

-- public_key is now the Ed25519 identity used for BOTH SIWS login (base58 of it
-- is the "address") and message-signature verification. Rotation is gone, so it
-- is stable for the account's lifetime.

-- ============================================================
-- 3. Notifications (first RLS + Realtime consumer)
-- ============================================================
-- One row per recipient per channel message (fanned out by send_message).
-- Read directly by the client via authenticated Realtime, scoped by RLS.
CREATE TABLE IF NOT EXISTS notifications (
  id          BIGSERIAL   PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  message_id  BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  sender_id   UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  read_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_unread
  ON notifications (user_id, id DESC) WHERE read_at IS NULL;

-- RLS: a user may only ever see/update their own notifications. This is the
-- one surface exposed to the client directly (everything else stays on edge
-- functions with the service role).
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notifications_select_own ON notifications;
CREATE POLICY notifications_select_own ON notifications
  FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS notifications_update_own ON notifications;
CREATE POLICY notifications_update_own ON notifications
  FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
-- No INSERT/DELETE policy: only the service role (send_message) writes rows.

-- Stream INSERTs to subscribed clients (RLS-filtered) via Postgres Changes.
ALTER PUBLICATION supabase_realtime ADD TABLE notifications;
