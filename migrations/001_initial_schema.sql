-- ============================================================
-- Rift Database Schema
-- Run this on a fresh Supabase instance to set up everything.
-- ============================================================

-- ⚠️  DEV ONLY — drop everything and start fresh.
-- TODO: Remove this entire block before going to production.
-- ============================================================
DROP FUNCTION IF EXISTS create_user_with_token(uuid, text, text, text, text, boolean, boolean, boolean, text, timestamptz);
DROP FUNCTION IF EXISTS claim_invite(text);

DROP TABLE IF EXISTS auth_challenges CASCADE;
DROP TABLE IF EXISTS tokens          CASCADE;
DROP TABLE IF EXISTS invites         CASCADE;
DROP TABLE IF EXISTS channels        CASCADE;
DROP TABLE IF EXISTS users           CASCADE;
DROP TABLE IF EXISTS servers         CASCADE;

DROP TYPE IF EXISTS channel_type;

SELECT cron.unschedule('cleanup-expired-challenges') WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-challenges');
SELECT cron.unschedule('cleanup-expired-tokens')     WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-tokens');
SELECT cron.unschedule('cleanup-expired-invites')    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-invites');
-- ============================================================

-- 1. Enum types
-- ============================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'channel_type') THEN
    CREATE TYPE channel_type AS ENUM ('voice', 'text');
  END IF;
END
$$;

-- 2. Tables
-- ============================================================

-- Servers: each Supabase instance hosts one server
CREATE TABLE IF NOT EXISTS servers (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at         TIMESTAMPTZ NOT NULL    DEFAULT now(),
  name               TEXT        NOT NULL,
  icon_url           TEXT,
  livekit_url        TEXT        NOT NULL,
  livekit_api_key    TEXT        NOT NULL,
  livekit_secret_key TEXT        NOT NULL
);

-- Users: per-server user profiles with cryptographic identity
CREATE TABLE IF NOT EXISTS users (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at         TIMESTAMPTZ NOT NULL    DEFAULT now(),
  server_id          UUID        NOT NULL    REFERENCES servers(id) ON DELETE CASCADE,
  username           TEXT        NOT NULL    UNIQUE,
  display_name       TEXT        NOT NULL,
  public_key         TEXT        NOT NULL    UNIQUE,
  stable_id          TEXT        NOT NULL    UNIQUE,
  is_banned          BOOLEAN     NOT NULL    DEFAULT false,
  is_server_admin    BOOLEAN     NOT NULL    DEFAULT false,
  is_channel_manager BOOLEAN     NOT NULL    DEFAULT false,
  can_create_tokens  BOOLEAN     NOT NULL    DEFAULT false
);

-- Channels: voice or text channels within a server
CREATE TABLE IF NOT EXISTS channels (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ  NOT NULL    DEFAULT now(),
  server_id    UUID         NOT NULL    REFERENCES servers(id) ON DELETE CASCADE,
  name         TEXT         NOT NULL,
  channel_type channel_type NOT NULL
);

-- Tokens: short-lived auth credentials (1 hour TTL), always linked to a user
CREATE TABLE IF NOT EXISTS tokens (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL    DEFAULT now(),
  server_id  UUID        NOT NULL    REFERENCES servers(id) ON DELETE CASCADE,
  token      TEXT        NOT NULL    UNIQUE,
  user_id    UUID        UNIQUE      REFERENCES users(id) ON DELETE SET NULL,
  expires_at TIMESTAMPTZ NOT NULL    DEFAULT now()
);

-- Invites: permission grants with reuse support — used to register new users
CREATE TABLE IF NOT EXISTS invites (
  id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at         TIMESTAMPTZ NOT NULL    DEFAULT now(),
  server_id          UUID        NOT NULL    REFERENCES servers(id) ON DELETE CASCADE,
  code               TEXT        NOT NULL    UNIQUE,
  is_server_admin    BOOLEAN     NOT NULL    DEFAULT false,
  is_channel_manager BOOLEAN     NOT NULL    DEFAULT false,
  can_create_tokens  BOOLEAN     NOT NULL    DEFAULT false,
  max_uses           INTEGER,                -- NULL = unlimited
  uses               INTEGER     NOT NULL    DEFAULT 0,
  expires_at         TIMESTAMPTZ             -- NULL = never expires
);

-- Auth challenges: short-lived nonces for challenge-response authentication.
-- One active challenge per public key (upsert replaces the old one).
CREATE TABLE IF NOT EXISTS auth_challenges (
  nonce      TEXT        PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL,
  public_key TEXT        NOT NULL    UNIQUE
);

-- 3. Indexes
-- ============================================================

-- Unique channel name per server
CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_server_name
  ON channels (server_id, name);

-- Faster token lookups
CREATE INDEX IF NOT EXISTS idx_tokens_server_id
  ON tokens (server_id);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id
  ON tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_tokens_expires_at
  ON tokens (expires_at);

-- Faster invite lookups
CREATE INDEX IF NOT EXISTS idx_invites_server_id
  ON invites (server_id);

-- Faster expired-invite cleanup
CREATE INDEX IF NOT EXISTS idx_invites_expires_at
  ON invites (expires_at)
  WHERE expires_at IS NOT NULL;

-- Faster expired challenge cleanup
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at
  ON auth_challenges (expires_at);

-- 4. Row Level Security
-- ============================================================
-- All data access goes through Edge Functions using SUPABASE_SERVICE_ROLE_KEY
-- (which bypasses RLS). Enabling RLS with no policies ensures the public
-- anon key cannot read or write anything directly.

ALTER TABLE servers         ENABLE ROW LEVEL SECURITY;
ALTER TABLE users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE channels        ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens          ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites         ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_challenges ENABLE ROW LEVEL SECURITY;

-- 5. Automatic cleanup of expired rows
-- ============================================================
-- Requires the pg_cron extension (enabled by default on Supabase).

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.schedule(
  'cleanup-expired-challenges',
  '*/5 * * * *',
  $$DELETE FROM auth_challenges WHERE expires_at < now()$$
);

SELECT cron.schedule(
  'cleanup-expired-tokens',
  '*/15 * * * *',
  $$DELETE FROM tokens WHERE expires_at < now()$$
);

SELECT cron.schedule(
  'cleanup-expired-invites',
  '*/15 * * * *',
  $$DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < now()$$
);

-- 6. Functions
-- ============================================================

-- Atomically claims one use of an invite by code.
-- Returns a JSONB object with a "reason" field:
--   "ok"        — success; invite data included
--   "expired"   — invite's expires_at has passed  (row is deleted)
--   "exhausted" — max_uses reached
--   "not_found" — no invite with that code
--
-- On success, the invite is deleted automatically once uses reaches max_uses,
-- so there is no need for a separate cleanup step for fully-claimed invites.
CREATE OR REPLACE FUNCTION claim_invite(p_invite_code text)
RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
  v_row     invites%ROWTYPE;
  v_exists  boolean;
  v_expired boolean;
BEGIN
  -- Atomically increment uses — only succeeds when:
  --   • the invite exists
  --   • it has not expired (expires_at IS NULL or still in the future)
  --   • it still has remaining uses (max_uses IS NULL or uses < max_uses)
  UPDATE invites
  SET    uses = uses + 1
  WHERE  code = p_invite_code
    AND  (max_uses IS NULL OR uses < max_uses)
    AND  (expires_at IS NULL OR expires_at > now())
  RETURNING * INTO v_row;

  IF FOUND THEN
    -- Fully claimed — delete so it can't be looked up again
    IF v_row.max_uses IS NOT NULL AND v_row.uses >= v_row.max_uses THEN
      DELETE FROM invites WHERE id = v_row.id;
    END IF;

    RETURN jsonb_build_object(
      'reason',             'ok',
      'id',                 v_row.id,
      'server_id',          v_row.server_id,
      'is_server_admin',    v_row.is_server_admin,
      'is_channel_manager', v_row.is_channel_manager,
      'can_create_tokens',  v_row.can_create_tokens
    );
  END IF;

  -- The update matched nothing — find out why
  SELECT
    EXISTS(SELECT 1 FROM invites WHERE code = p_invite_code),
    EXISTS(SELECT 1 FROM invites WHERE code = p_invite_code
                                   AND expires_at IS NOT NULL
                                   AND expires_at <= now())
  INTO v_exists, v_expired;

  IF v_expired THEN
    -- Clean up the expired invite
    DELETE FROM invites WHERE code = p_invite_code;
    RETURN jsonb_build_object('reason', 'expired');
  ELSIF v_exists THEN
    RETURN jsonb_build_object('reason', 'exhausted');
  ELSE
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
END;
$$;

-- Inserts a new user AND their first auth token in a single transaction.
-- If either insert fails (e.g. duplicate public_key or token collision) the
-- whole operation rolls back atomically — no ghost user rows are left behind.
CREATE OR REPLACE FUNCTION create_user_with_token(
  p_server_id           uuid,
  p_username            text,
  p_display_name        text,
  p_public_key          text,
  p_stable_id           text,
  p_is_server_admin     boolean,
  p_is_channel_manager  boolean,
  p_can_create_tokens   boolean,
  p_auth_token          text,
  p_token_expires_at    timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
  v_user_id uuid;
BEGIN
  INSERT INTO users (
    server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens
  ) VALUES (
    p_server_id, p_username, p_display_name, p_public_key, p_stable_id,
    p_is_server_admin, p_is_channel_manager, p_can_create_tokens
  )
  RETURNING id INTO v_user_id;

  -- In the same transaction: if this insert fails the user row is rolled back
  INSERT INTO tokens (server_id, token, user_id, expires_at)
  VALUES (p_server_id, p_auth_token, v_user_id, p_token_expires_at);

  RETURN jsonb_build_object('user_id', v_user_id);
END;
$$;

-- Only the service_role (used by edge functions) may call these internal RPCs.
-- Revoking from PUBLIC removes access for the anon and authenticated roles,
-- which are reachable via the public anon key.
REVOKE EXECUTE ON FUNCTION claim_invite(text)  FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION claim_invite(text)  TO   service_role;

REVOKE EXECUTE ON FUNCTION create_user_with_token(uuid, text, text, text, text, boolean, boolean, boolean, text, timestamptz) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION create_user_with_token(uuid, text, text, text, text, boolean, boolean, boolean, text, timestamptz) TO   service_role;

-- 7. Storage bucket for server assets (icons, etc.)
-- ============================================================

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'servers',
  'servers',
  true,
  5242880,  -- 5 MB
  '{image/jpeg,image/png,image/gif,image/webp}'
)
ON CONFLICT (id) DO NOTHING;
