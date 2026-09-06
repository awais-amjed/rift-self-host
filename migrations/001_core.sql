-- ============================================================
-- Rift self-hosted server — 001: The server itself
-- ============================================================
-- Tables, the policies that guard them, the RPCs that replace privileged
-- endpoints, what clients may subscribe to, buckets, and the scheduled
-- cleanup. Everything a server is before any feature is added to it.
--
-- Was 6 files: 001_schema, 002_security, 003_api, 004_realtime, 005_storage, 006_jobs.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 001: schema
-- ============================================================
-- This file replaces migrations 001–015. Those were fifteen files describing a
-- database that had been rebuilt underneath them: token auth removed and
-- replaced by GoTrue/SIWS, columns added and dropped, tables introduced by one
-- migration and reshaped by three later ones. Nobody could read the schema off
-- them, and two tables were left without RLS because the migration that created
-- them forgot — which, with Supabase's default grants, meant anyone holding a
-- server's anon key could read and delete every message on it.
--
-- No server outside this repo has ever run these, so the honest fix is a single
-- description of the schema as it should be, with the security expressed in one
-- place (002) rather than inferred from a sequence of edits.
--
-- Read the files in order:
--   001_schema.sql    tables, keys, indexes, attestation triggers
--   002_security.sql  grants, RLS, and every policy
--   003_api.sql       the RPCs that replace privileged edge functions
--   004_realtime.sql  what clients may subscribe to
--   005_storage.sql   buckets and their policies
--   006_jobs.sql      scheduled cleanup

-- pgcrypto backs new_invite_code(); pg_cron is declared by 006, which is the
-- only file that schedules anything.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Types
-- ============================================================

DO $$ BEGIN
  CREATE TYPE channel_type AS ENUM ('voice', 'text');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- What a read cursor points at. One table covers channels and DMs because the
-- question is identical in both cases — "how far has this person read" — and
-- keeping it in one place is what lets a single client path badge both.
DO $$ BEGIN
  CREATE TYPE read_scope AS ENUM ('channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- Servers
-- ============================================================
-- One Supabase project can host several servers (identity is derived per
-- (host, server_id), so the same person joining two of them has two distinct
-- GoTrue accounts and two rows in `users`).

CREATE TABLE IF NOT EXISTS servers (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  name        TEXT        NOT NULL,
  icon_url    TEXT,
  livekit_url TEXT        NOT NULL
);

-- LiveKit credentials live in their own table, not as columns on `servers`.
--
-- They used to sit beside the name and icon, which made the whole row
-- unshowable to a client: every read had to be laundered through an edge
-- function or the API secret went with it. Split out, `servers` becomes
-- ordinary public metadata a member can select directly, and the secret sits
-- in a table with RLS and no policy at all — unreachable by any client, only
-- ever read by `get_channel_token` on the service role.
CREATE TABLE IF NOT EXISTS server_secrets (
  server_id          UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  livekit_api_key    TEXT NOT NULL,
  livekit_secret_key TEXT NOT NULL
);

-- ============================================================
-- Members
-- ============================================================
-- `users.id` IS the GoTrue uid, so every ownership rule anywhere in this schema
-- is `= auth.uid()` with no join.

CREATE TABLE IF NOT EXISTS users (
  id                 UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id          UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  username           TEXT        NOT NULL,
  display_name       TEXT        NOT NULL,
  -- Ed25519 signing key (base58 of it is the SIWS "address").
  public_key         TEXT        NOT NULL,
  -- Stable per-(host, server) identifier derived from the seed.
  stable_id          TEXT        NOT NULL,
  -- X25519 key others seal to. Null until the client publishes it.
  chat_public_key    TEXT,
  avatar_path        TEXT,
  is_banned          BOOLEAN     NOT NULL DEFAULT false,
  is_server_admin    BOOLEAN     NOT NULL DEFAULT false,
  is_channel_manager BOOLEAN     NOT NULL DEFAULT false,
  can_create_tokens  BOOLEAN     NOT NULL DEFAULT false,
  is_muted           BOOLEAN     NOT NULL DEFAULT false,
  is_deafened        BOOLEAN     NOT NULL DEFAULT false,
  -- Per-server uniqueness, not global: two servers in one project are two
  -- different communities and may each have a "sam".
  UNIQUE (server_id, username),
  UNIQUE (server_id, public_key),
  UNIQUE (server_id, stable_id)
);

CREATE INDEX IF NOT EXISTS idx_users_server ON users (server_id);

-- ============================================================
-- Channels and invites
-- ============================================================

CREATE TABLE IF NOT EXISTS channels (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  server_id    UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name         TEXT         NOT NULL,
  channel_type channel_type NOT NULL,
  UNIQUE (server_id, name)
);

-- Base58, 10 characters — the same shape the edge function used to mint, moved
-- to a column default so an invite can be created by an ordinary INSERT under
-- RLS instead of needing a privileged endpoint.
-- search_path includes `extensions`: that is where Supabase installs pgcrypto,
-- and a column default runs with the *inserting* role's path, which doesn't
-- have it.
CREATE OR REPLACE FUNCTION new_invite_code() RETURNS TEXT
  LANGUAGE plpgsql VOLATILE SET search_path = public, extensions AS $$
DECLARE
  alphabet CONSTANT TEXT :=
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  out TEXT := '';
  b   INTEGER;
BEGIN
  WHILE length(out) < 10 LOOP
    b := get_byte(gen_random_bytes(1), 0);
    -- Reject the tail of the byte range so every character stays equally
    -- likely (58 does not divide 256).
    IF b < 232 THEN
      out := out || substr(alphabet, (b % 58) + 1, 1);
    END IF;
  END LOOP;
  RETURN out;
END; $$;

CREATE TABLE IF NOT EXISTS invites (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id          UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  -- Who minted it. New here: it is what lets a member manage their own invites
  -- under RLS without being able to enumerate everyone else's codes.
  created_by         UUID        REFERENCES users(id) ON DELETE SET NULL,
  code               TEXT        NOT NULL UNIQUE DEFAULT new_invite_code(),
  is_server_admin    BOOLEAN     NOT NULL DEFAULT false,
  is_channel_manager BOOLEAN     NOT NULL DEFAULT false,
  can_create_tokens  BOOLEAN     NOT NULL DEFAULT false,
  max_uses           INTEGER,
  uses               INTEGER     NOT NULL DEFAULT 0,
  expires_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_invites_server ON invites (server_id);
CREATE INDEX IF NOT EXISTS idx_invites_expires
  ON invites (expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================
-- Messages
-- ============================================================
-- Opaque E2E envelopes. The server stores and orders them and attests who sent
-- them and when; it can't read them.
--
-- The length limits are new. They lived in TypeScript
-- (`_shared/chat.ts::checkEnvelopeFields`) back when every write went through
-- an edge function. Clients insert directly now, so the constraint has to be
-- where the row is: a check in the database is the only validation a modified
-- client cannot skip.

CREATE TABLE IF NOT EXISTS messages (
  id          BIGSERIAL   PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  sender_id   UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  ciphertext  TEXT        NOT NULL CHECK (length(ciphertext) <= 16384),
  nonce       TEXT        NOT NULL CHECK (length(nonce)      <= 64),
  signature   TEXT        NOT NULL CHECK (length(signature)  <= 128),
  key_version INTEGER     NOT NULL CHECK (key_version >= 1),
  edited_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (channel_id, id);

CREATE TABLE IF NOT EXISTS dm_messages (
  id           BIGSERIAL   PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext   TEXT        NOT NULL CHECK (length(ciphertext) <= 16384),
  nonce        TEXT        NOT NULL CHECK (length(nonce)      <= 64),
  signature    TEXT        NOT NULL CHECK (length(signature)  <= 128),
  key_version  INTEGER     NOT NULL CHECK (key_version >= 1),
  edited_at    TIMESTAMPTZ,
  CHECK (sender_id <> recipient_id)
);

-- Order-independent pair index: a conversation is looked up from either side.
CREATE INDEX IF NOT EXISTS idx_dm_messages_pair ON dm_messages
  (LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id), id);
CREATE INDEX IF NOT EXISTS idx_dm_messages_recipient ON dm_messages (recipient_id, id);
CREATE INDEX IF NOT EXISTS idx_dm_messages_sender    ON dm_messages (sender_id, id);

-- ============================================================
-- Attestation
-- ============================================================
-- What the server promises about a message: who wrote it and when. With direct
-- inserts, a client controls the row it posts, so the promise has to be
-- enforced here — otherwise anyone could post as anyone, or backdate.
--
-- Service-role writes (registration, maintenance) have no auth.uid() and are
-- left alone, so seeding and edge functions still work.

CREATE OR REPLACE FUNCTION attest_message() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;
    RETURN NEW;
  END IF;

  -- An edit may only change the envelope. Identity, placement and time of
  -- sending are the server's word and stay put; edited_at is stamped here
  -- rather than trusted from the client.
  NEW.id         := OLD.id;
  NEW.sender_id  := OLD.sender_id;
  NEW.created_at := OLD.created_at;
  IF TG_TABLE_NAME = 'messages' THEN
    NEW.channel_id := OLD.channel_id;
  ELSE
    NEW.recipient_id := OLD.recipient_id;
  END IF;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS attest_messages ON messages;
CREATE TRIGGER attest_messages BEFORE INSERT OR UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION attest_message();

DROP TRIGGER IF EXISTS attest_dm_messages ON dm_messages;
CREATE TRIGGER attest_dm_messages BEFORE INSERT OR UPDATE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION attest_message();

-- ============================================================
-- Reactions
-- ============================================================
-- Deliberately NOT E2E: the server sees who reacted with which emoji. Accepted
-- metadata cost of a reaction UX (ARCHITECTURE.md §4) — message *content* stays
-- encrypted.

CREATE TABLE IF NOT EXISTS message_reactions (
  message_id BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

CREATE TABLE IF NOT EXISTS dm_message_reactions (
  message_id BIGINT      NOT NULL REFERENCES dm_messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)       ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

-- ============================================================
-- Channel keyring
-- ============================================================
-- Each channel key, sealed once per member (Design 2). The server holds only
-- ciphertext it cannot open.

CREATE TABLE IF NOT EXISTS channel_keyring (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL CHECK (key_version >= 1),
  user_id              UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_by           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  UNIQUE (channel_id, key_version, user_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_keyring_user ON channel_keyring (user_id);

-- ============================================================
-- Read state
-- ============================================================
-- One cursor per conversation: the newest message id this member has read.
--
-- This replaces the `notifications` table, which fanned out one row per
-- recipient per message purely so the client could count unread. That cost a
-- write per member per message and a retention job to keep it from growing
-- forever. A cursor is one row per conversation, written when you actually read
-- something, and it produces the same badges — see unread_counts() in 003.
--
-- Central DMs keep the same shape, so both tiers can share one client path.

CREATE TABLE IF NOT EXISTS read_state (
  user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope        read_scope  NOT NULL,
  -- Channel id for 'channel', the other person's user id for 'dm'.
  scope_id     UUID        NOT NULL,
  last_read_id BIGINT      NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);


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

-- You can always read your own row, even banned.
--
-- Every other policy here routes through app.server_id(), which returns NULL
-- for a banned member — so a ban did not merely take their access away, it
-- took away any way of finding out. The client had nothing to read and nothing
-- to be told: the app simply stopped working, which is indistinguishable from
-- being broken.
--
-- This is the one row that has to stay legible. It is their own, they could
-- read it a moment ago, and `users` is in the realtime publication — so the
-- UPDATE that bans them reaches them, and so does the one that lifts it, which
-- is what lets a client recover without a restart.
DROP POLICY IF EXISTS users_select_self ON users;
CREATE POLICY users_select_self ON users FOR SELECT TO authenticated
  USING (id = auth.uid());

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


-- ============================================================
-- Rift self-hosted server — 003: RPCs
-- ============================================================
-- What's left after RLS. Two kinds of thing end up here:
--
--   * writes that touch columns the caller must not own (moderation flags,
--     permissions). RLS is row-level, so "an admin may ban but not rename"
--     cannot be a policy — it is a function that writes exactly those columns.
--   * reads that aren't a single table query (unread counts, the conversation
--     list), which would otherwise be an edge function doing in TypeScript what
--     one SQL statement does here.
--
-- Everything else the client needs is a plain PostgREST call against 002's
-- policies. Edge functions now exist only where a secret or a pre-membership
-- bootstrap step is genuinely involved: login, register, resolve_invite,
-- create_server, get_channel_token.

-- ============================================================
-- Registration (service role only — called by the `register` function)
-- ============================================================

CREATE OR REPLACE FUNCTION register_user(
  p_invite_code  TEXT,
  p_user_id      UUID,
  p_public_key   TEXT,
  p_stable_id    TEXT,
  p_username     TEXT,
  p_display_name TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_invite invites%ROWTYPE;
BEGIN
  SELECT * INTO v_invite FROM invites WHERE code = p_invite_code FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
  IF v_invite.expires_at IS NOT NULL AND v_invite.expires_at <= now() THEN
    DELETE FROM invites WHERE id = v_invite.id;
    RETURN jsonb_build_object('reason', 'expired');
  END IF;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses >= v_invite.max_uses THEN
    RETURN jsonb_build_object('reason', 'exhausted');
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
    RETURN jsonb_build_object('reason', 'already_registered');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id
                AND (public_key = p_public_key OR stable_id = p_stable_id)) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id AND username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager, true
  );

  -- Start every channel's cursor at whatever is already there. Without this a
  -- new member's first sight of the server is every channel screaming with
  -- unread counts for messages sent before they arrived — which they can't
  -- decrypt anyway, since keys are only wrapped for them going forward.
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object('reason', 'ok', 'server_id', v_invite.server_id);
END; $$;

-- ============================================================
-- Moderation and permissions
-- ============================================================
-- SECURITY DEFINER so the caller never needs UPDATE on someone else's row —
-- these write the moderation/permission columns and nothing else, which is
-- exactly the guarantee a policy cannot give.

CREATE OR REPLACE FUNCTION moderate_user(
  p_target   UUID,
  p_muted    BOOLEAN DEFAULT NULL,
  p_deafened BOOLEAN DEFAULT NULL,
  p_banned   BOOLEAN DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_target users%ROWTYPE;
BEGIN
  -- Two permissions, because these are not the same act. Muting and deafening
  -- are what a channel manager is *for* — they already move and disconnect
  -- people — and gating them on admin meant the client offered buttons that
  -- always came back not_authorized. Banning stays with admins: it ends
  -- somebody's membership, which is the same weight as granting a role.
  IF p_banned IS NOT NULL THEN
    IF NOT app.is_admin() THEN
      RAISE EXCEPTION 'not_authorized';
    END IF;
  ELSIF NOT app.can_manage_channels() THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;

  SELECT * INTO v_target FROM users
   WHERE id = p_target AND server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  IF v_target.id = auth.uid() THEN
    RAISE EXCEPTION 'cannot_moderate_self';
  END IF;
  -- An admin is not a moderation target for another admin. Removing that
  -- standing is a permission change, and it goes through the other function.
  IF v_target.is_server_admin THEN
    RAISE EXCEPTION 'cannot_moderate_admin';
  END IF;

  UPDATE users SET
    is_muted    = COALESCE(p_muted,    is_muted),
    is_deafened = COALESCE(p_deafened, is_deafened),
    is_banned   = COALESCE(p_banned,   is_banned)
   WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION set_user_permissions(
  p_target             UUID,
  p_is_server_admin    BOOLEAN DEFAULT NULL,
  p_is_channel_manager BOOLEAN DEFAULT NULL,
  p_can_create_tokens  BOOLEAN DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- You can only grant what you hold. Admin holds everything, so in practice
  -- this is the admin check plus a guard against a manager minting admins.
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF p_target = auth.uid() THEN
    RAISE EXCEPTION 'cannot_change_own_permissions';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users
                  WHERE id = p_target AND server_id = app.server_id()) THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;

  UPDATE users SET
    is_server_admin    = COALESCE(p_is_server_admin,    is_server_admin),
    is_channel_manager = COALESCE(p_is_channel_manager, is_channel_manager),
    can_create_tokens  = COALESCE(p_can_create_tokens,  can_create_tokens)
   WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- Unread
-- ============================================================
-- Every badge in the app, in one round trip. SECURITY INVOKER on purpose: the
-- counts are filtered by the same policies as a direct read, so this can't
-- report on a channel the caller can't see.

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'channels', COALESCE((
      SELECT jsonb_object_agg(channel_id, n) FROM (
        SELECT m.channel_id, count(*) AS n
          FROM messages m
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'channel'
           AND r.scope_id = m.channel_id
         WHERE m.sender_id <> auth.uid()
           AND m.id > COALESCE(r.last_read_id, 0)
         GROUP BY m.channel_id
      ) c), '{}'::jsonb),
    'dms', COALESCE((
      SELECT jsonb_object_agg(sender_id, n) FROM (
        SELECT d.sender_id, count(*) AS n
          FROM dm_messages d
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'dm'
           AND r.scope_id = d.sender_id
         WHERE d.recipient_id = auth.uid()
           AND d.id > COALESCE(r.last_read_id, 0)
         GROUP BY d.sender_id
      ) d), '{}'::jsonb)
  );
$$;

-- Move a cursor forward. Never backward: two devices race on the same
-- conversation, and the one that read less must not un-read what the other
-- read. Passing 0 means "up to whatever is newest right now".
CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_target BIGINT := p_last_read_id;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    IF p_scope = 'channel' THEN
      SELECT COALESCE(max(m.id), 0) INTO v_target
        FROM messages m WHERE m.channel_id = p_scope_id;
    ELSE
      SELECT COALESCE(max(d.id), 0) INTO v_target
        FROM dm_messages d
       WHERE d.sender_id = p_scope_id AND d.recipient_id = auth.uid();
    END IF;
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (auth.uid(), p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
              updated_at   = now()
    RETURNING last_read_id INTO v_target;

  RETURN v_target;
END; $$;

-- "Mark all as read" for a whole server: every channel and every conversation
-- moved to whatever is newest. One statement each rather than a round trip per
-- channel from the client.
CREATE OR REPLACE FUNCTION mark_all_read() RETURNS VOID
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT auth.uid(), 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT auth.uid(), 'dm', d.sender_id, max(d.id)
    FROM dm_messages d
   WHERE d.recipient_id = auth.uid()
   GROUP BY d.sender_id
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();
END; $$;

-- ============================================================
-- DM conversation list
-- ============================================================
-- The newest envelope per peer plus that peer's identity material. This was an
-- edge function that pulled a thousand rows and grouped them in TypeScript;
-- DISTINCT ON does it in the database and returns only what's shown.

CREATE OR REPLACE FUNCTION dm_conversations() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(row ORDER BY (row->'last_message'->>'id')::BIGINT DESC), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'peer_id',               u.id,
               'peer_name',             u.display_name,
               'peer_username',         u.username,
               'peer_avatar_path',      u.avatar_path,
               'peer_chat_public_key',  u.chat_public_key,
               'peer_public_key',       u.public_key,
               'last_message', jsonb_build_object(
                 'id',           l.id,
                 'created_at',   l.created_at,
                 'sender_id',    l.sender_id,
                 'recipient_id', l.recipient_id,
                 'ciphertext',   l.ciphertext,
                 'nonce',        l.nonce,
                 'signature',    l.signature,
                 'key_version',  l.key_version,
                 'edited_at',    l.edited_at
               )
             ) AS row
        FROM (
          SELECT DISTINCT ON (peer) *
            FROM (
              SELECT d.*,
                     CASE WHEN d.sender_id = auth.uid()
                          THEN d.recipient_id ELSE d.sender_id END AS peer
                FROM dm_messages d
            ) paired
           ORDER BY peer, id DESC
        ) l
        JOIN users u ON u.id = l.peer
    ) rows;
$$;

-- ============================================================
-- Function privileges
-- ============================================================
-- Postgres grants EXECUTE to PUBLIC by default, which would expose
-- register_user to anyone. Same discipline as the tables: revoke everything,
-- then hand back only what a member is meant to call.

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION new_invite_code()        TO authenticated;
GRANT EXECUTE ON FUNCTION unread_counts()          TO authenticated;
GRANT EXECUTE ON FUNCTION mark_read(read_scope, UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION mark_all_read()          TO authenticated;
GRANT EXECUTE ON FUNCTION dm_conversations()       TO authenticated;
GRANT EXECUTE ON FUNCTION moderate_user(UUID, BOOLEAN, BOOLEAN, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION set_user_permissions(UUID, BOOLEAN, BOOLEAN, BOOLEAN) TO authenticated;

-- register_user is deliberately not granted: it is the service role's, called
-- by the `register` edge function, which is the only thing that has both the
-- invite code and no membership yet.


-- ============================================================
-- Rift self-hosted server — 004: realtime
-- ============================================================
-- What a client may subscribe to. Realtime re-checks 002's policies per
-- subscriber for every change, so a member only ever receives rows they could
-- have selected — a message from a channel on another server in the same
-- project is never delivered.
--
-- This is what lets the `notifications` table go. Badges used to need a fanned
-- out row per recipient because that row was the only thing a client was
-- allowed to watch. Now it watches the messages themselves.
--
-- Note that a policy consulting an RLS-locked table always evaluates false
-- here, silently — which looks exactly like Realtime being broken. 002's
-- helpers are SECURITY DEFINER for that reason.

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE messages;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE dm_messages;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Reactions are watched so a tally updates live without a doorbell ping.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE message_reactions;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE dm_message_reactions;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Members: a rename, a new avatar, a mute or a ban reaches everyone looking at
-- the member list without polling.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE users;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Channels: created, renamed and deleted channels restructure the sidebar.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE channels;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;


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


-- ============================================================
-- Rift self-hosted server — 006: scheduled cleanup
-- ============================================================
-- One job. There used to be four: two swept the auth-challenge and token tables
-- that GoTrue replaced, and one pruned `notifications` — a table that existed
-- only to be counted and therefore only to be cleaned up. Read cursors don't
-- accumulate, so nothing prunes them.
--
-- Messages are never swept here. A self-hosted server is somebody's own
-- hardware and their own retention policy; deleting their history on a timer is
-- the central tier's bargain, not this one's.

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.unschedule('cleanup-expired-invites')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-invites');

SELECT cron.schedule(
  'cleanup-expired-invites',
  '0 * * * *',
  $$DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < now()$$
);
