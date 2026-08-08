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

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_cron;

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
