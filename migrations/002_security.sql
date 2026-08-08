-- ============================================================
-- Rift self-hosted server — 002: grants, RLS, policies
-- ============================================================
-- Every rule about who may see or change what lives in this file.
--
-- It exists because the old arrangement was "clients never touch tables, so
-- RLS doesn't matter much" — and that was only ever true by accident. Supabase
-- grants `anon` full DML on public tables by default, so a table whose
-- migration forgot to enable RLS was readable *and deletable* by anyone holding
-- the server's anon key, which every member has and every invite hands out.
-- `messages`, `dm_messages` and `channel_keyring` were all in that state.
--
-- Two rules keep that from recurring:
--   1. `anon` is revoked from everything. An unauthenticated request can do
--      nothing at all, whatever a policy says.
--   2. Every table has RLS enabled here, in one file, next to its policies.
--
-- Where a table has both self-writable and privileged columns, the split is a
-- column-level GRANT rather than a policy — RLS is row-level only, so a policy
-- that lets you edit your display name would also let you set is_server_admin.
-- Postgres enforces the column list; PostgREST returns 403 on anything else.

-- ============================================================
-- 1. Helpers
-- ============================================================
-- In their own schema so PostgREST can't expose them as RPCs, and
-- SECURITY DEFINER so a policy never depends on the caller being able to read
-- the table it consults. That is not a nicety: a policy on `messages` that
-- selects from `channels` sees nothing (channels is itself RLS-locked), so the
-- policy silently denies everything — including, in Realtime's case, every
-- change it should have delivered.
--
-- The ban check lives inside these, so revocation stays immediate on the
-- direct-access path: a banned member's `app.server_id()` is null and every
-- policy built on it fails from the next statement onward.

CREATE SCHEMA IF NOT EXISTS app;
GRANT USAGE ON SCHEMA app TO authenticated;

CREATE OR REPLACE FUNCTION app.server_id() RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.server_id FROM users u WHERE u.id = auth.uid() AND NOT u.is_banned
$$;

CREATE OR REPLACE FUNCTION app.is_admin() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.can_manage_channels() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin OR u.is_channel_manager FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.can_invite() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin OR u.can_create_tokens FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.channel_server_id(p_channel UUID) RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.server_id FROM channels c WHERE c.id = p_channel
$$;

-- Is this person a live member of my server? Used for "may I DM them".
CREATE OR REPLACE FUNCTION app.is_co_member(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_user AND NOT u.is_banned
                    AND u.server_id = app.server_id())
$$;

-- ...and have they published a chat key? Sealing to someone who hasn't is a
-- message nobody can ever open.
CREATE OR REPLACE FUNCTION app.can_receive_dm(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_user AND NOT u.is_banned
                    AND u.chat_public_key IS NOT NULL
                    AND u.server_id = app.server_id())
$$;

CREATE OR REPLACE FUNCTION app.can_see_message(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM messages m
                  WHERE m.id = p_message
                    AND app.channel_server_id(m.channel_id) = app.server_id())
$$;

CREATE OR REPLACE FUNCTION app.can_see_dm(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM dm_messages d
                  WHERE d.id = p_message
                    AND auth.uid() IN (d.sender_id, d.recipient_id))
$$;

-- ============================================================
-- 2. Grants
-- ============================================================

-- Nothing unauthenticated, ever — including tables added later.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES    FROM anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon;

-- Start from nothing for members too, then hand back exactly what the client
-- needs. RLS decides *which rows*; these decide *which columns and verbs*.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;

-- Read-only. Renaming a server is done through `update_server`, which is an
-- edge function because the same dialog writes the LiveKit API secret — and
-- that has no client-reachable path at all.
GRANT SELECT                       ON servers  TO authenticated;

GRANT SELECT                       ON users    TO authenticated;
-- Your own profile, and nothing else on the row: moderation flags and
-- permissions are not yours to write, they go through the RPCs in 003.
GRANT UPDATE (display_name, chat_public_key, avatar_path) ON users TO authenticated;

GRANT SELECT, INSERT, DELETE       ON channels TO authenticated;
GRANT UPDATE (name)                ON channels TO authenticated;

GRANT SELECT, INSERT, DELETE       ON invites  TO authenticated;

GRANT SELECT, INSERT, DELETE       ON messages TO authenticated;
GRANT UPDATE (ciphertext, nonce, signature, key_version) ON messages TO authenticated;
GRANT SELECT, INSERT, DELETE       ON dm_messages TO authenticated;
GRANT UPDATE (ciphertext, nonce, signature, key_version) ON dm_messages TO authenticated;
GRANT USAGE ON SEQUENCE messages_id_seq    TO authenticated;
GRANT USAGE ON SEQUENCE dm_messages_id_seq TO authenticated;

GRANT SELECT, INSERT, DELETE       ON message_reactions    TO authenticated;
GRANT SELECT, INSERT, DELETE       ON dm_message_reactions TO authenticated;

-- A keyring row is written once and never edited: a rewrap is a new version.
GRANT SELECT, INSERT               ON channel_keyring TO authenticated;

GRANT SELECT, INSERT               ON read_state TO authenticated;
GRANT UPDATE (last_read_id, updated_at) ON read_state TO authenticated;

-- server_secrets is deliberately absent. No grant, no policy, no client path.

-- ============================================================
-- 3. Row-level security
-- ============================================================

ALTER TABLE servers              ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_secrets       ENABLE ROW LEVEL SECURITY;
ALTER TABLE users                ENABLE ROW LEVEL SECURITY;
ALTER TABLE channels             ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites              ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages             ENABLE ROW LEVEL SECURITY;
ALTER TABLE dm_messages          ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_reactions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE dm_message_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_keyring      ENABLE ROW LEVEL SECURITY;
ALTER TABLE read_state           ENABLE ROW LEVEL SECURITY;

-- ---------- servers ----------
DROP POLICY IF EXISTS servers_select ON servers;
CREATE POLICY servers_select ON servers FOR SELECT TO authenticated
  USING (id = app.server_id());

-- ---------- users ----------
DROP POLICY IF EXISTS users_select_members ON users;
CREATE POLICY users_select_members ON users FOR SELECT TO authenticated
  USING (server_id = app.server_id());

DROP POLICY IF EXISTS users_update_self ON users;
CREATE POLICY users_update_self ON users FOR UPDATE TO authenticated
  USING (id = auth.uid() AND server_id = app.server_id())
  WITH CHECK (id = auth.uid() AND server_id = app.server_id());

-- ---------- channels ----------
DROP POLICY IF EXISTS channels_select ON channels;
CREATE POLICY channels_select ON channels FOR SELECT TO authenticated
  USING (server_id = app.server_id());

DROP POLICY IF EXISTS channels_write_managers ON channels;
CREATE POLICY channels_write_managers ON channels FOR INSERT TO authenticated
  WITH CHECK (server_id = app.server_id() AND app.can_manage_channels());

DROP POLICY IF EXISTS channels_update_managers ON channels;
CREATE POLICY channels_update_managers ON channels FOR UPDATE TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels())
  WITH CHECK (server_id = app.server_id() AND app.can_manage_channels());

DROP POLICY IF EXISTS channels_delete_managers ON channels;
CREATE POLICY channels_delete_managers ON channels FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels());

-- ---------- invites ----------
-- Only your own: a code is a bearer token, so members must not be able to read
-- each other's.
DROP POLICY IF EXISTS invites_select_own ON invites;
CREATE POLICY invites_select_own ON invites FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND created_by = auth.uid());

-- The delegation rule — you can only grant what you hold — as a row predicate.
DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (NOT is_server_admin    OR app.is_admin())
    AND (NOT is_channel_manager OR app.can_manage_channels())
    AND (NOT can_create_tokens  OR app.can_invite())
  );

DROP POLICY IF EXISTS invites_delete_own ON invites;
CREATE POLICY invites_delete_own ON invites FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND created_by = auth.uid());

-- ---------- messages ----------
DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (app.channel_server_id(channel_id) = app.server_id());

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.channel_server_id(channel_id) = app.server_id()
    AND sender_id = auth.uid()
  );

DROP POLICY IF EXISTS messages_update_own ON messages;
CREATE POLICY messages_update_own ON messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid()
         AND app.channel_server_id(channel_id) = app.server_id())
  WITH CHECK (sender_id = auth.uid());

-- Sender, or a moderator. Editing has no moderator case on purpose: an admin
-- may remove a message but never rewrite one under its author's name.
DROP POLICY IF EXISTS messages_delete ON messages;
CREATE POLICY messages_delete ON messages FOR DELETE TO authenticated
  USING (
    app.channel_server_id(channel_id) = app.server_id()
    AND (sender_id = auth.uid() OR app.can_manage_channels())
  );

-- ---------- dm_messages ----------
DROP POLICY IF EXISTS dm_messages_select ON dm_messages;
CREATE POLICY dm_messages_select ON dm_messages FOR SELECT TO authenticated
  USING (auth.uid() IN (sender_id, recipient_id));

DROP POLICY IF EXISTS dm_messages_insert ON dm_messages;
CREATE POLICY dm_messages_insert ON dm_messages FOR INSERT TO authenticated
  WITH CHECK (sender_id = auth.uid() AND app.can_receive_dm(recipient_id));

DROP POLICY IF EXISTS dm_messages_update_own ON dm_messages;
CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid()) WITH CHECK (sender_id = auth.uid());

DROP POLICY IF EXISTS dm_messages_delete_own ON dm_messages;
CREATE POLICY dm_messages_delete_own ON dm_messages FOR DELETE TO authenticated
  USING (sender_id = auth.uid());

-- ---------- reactions ----------
DROP POLICY IF EXISTS message_reactions_select ON message_reactions;
CREATE POLICY message_reactions_select ON message_reactions FOR SELECT TO authenticated
  USING (app.can_see_message(message_id));

DROP POLICY IF EXISTS message_reactions_insert ON message_reactions;
CREATE POLICY message_reactions_insert ON message_reactions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND app.can_see_message(message_id));

DROP POLICY IF EXISTS message_reactions_delete_own ON message_reactions;
CREATE POLICY message_reactions_delete_own ON message_reactions FOR DELETE TO authenticated
  USING (user_id = auth.uid());

DROP POLICY IF EXISTS dm_reactions_select ON dm_message_reactions;
CREATE POLICY dm_reactions_select ON dm_message_reactions FOR SELECT TO authenticated
  USING (app.can_see_dm(message_id));

DROP POLICY IF EXISTS dm_reactions_insert ON dm_message_reactions;
CREATE POLICY dm_reactions_insert ON dm_message_reactions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND app.can_see_dm(message_id));

DROP POLICY IF EXISTS dm_reactions_delete_own ON dm_message_reactions;
CREATE POLICY dm_reactions_delete_own ON dm_message_reactions FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- ---------- channel_keyring ----------
-- Members may read the whole channel's keyring, not just their own row: the
-- key-sweep needs to know who is still missing a wrap. The rows are sealed to
-- someone else's key, so seeing them reveals nothing but membership, which
-- members already have.
DROP POLICY IF EXISTS channel_keyring_select ON channel_keyring;
CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (app.channel_server_id(channel_id) = app.server_id());

DROP POLICY IF EXISTS channel_keyring_insert ON channel_keyring;
CREATE POLICY channel_keyring_insert ON channel_keyring FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.channel_server_id(channel_id) = app.server_id()
    AND app.is_co_member(user_id)
  );

-- ---------- read_state ----------
DROP POLICY IF EXISTS read_state_own ON read_state;
CREATE POLICY read_state_own ON read_state FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
