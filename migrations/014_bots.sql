-- ============================================================
-- Rift self-hosted server — 014: bot identity
-- ============================================================
-- BOTS.md phase 1: a bot that exists and does nothing.
--
-- **A bot is a user whose seed lives in a config file instead of on a phone.**
-- There is no separate bot API, no bot token format, no second auth path — the
-- same `users` row, the same SIWS login, the same JWT, the same RLS. That is
-- not a shortcut. It is what stops the bot surface drifting away from the app
-- surface: a capability the app has, a bot has, under the same policies.
--
-- So this migration adds almost nothing. One flag saying which rows are bots,
-- one flag on invites saying which invites mint them, and one guard that is the
-- whole reason the flag has to exist at all.
--
-- ---------- the guard is the feature ----------
--
-- BOTS.md §2: bots never hold channel keys. Not because a policy forbids
-- reading, but because a wrapped key *is* read access — arithmetic, not a rule,
-- and unlike a rule it cannot be taken back. Everything a bot legitimately does
-- happens over messages the server can already read (§3, migration 013).
--
-- §6 names the way that goes wrong, and it is not an attacker. `get_channel_key`
-- returns `members_missing` — members with a published chat key and no entry at
-- the current version — and **any member's client heals them**, automatically,
-- as a courtesy. A bot publishes a chat key like everybody else. Left alone, the
-- first member to open the channel would wrap the key for it, silently, having
-- been asked to do nothing.
--
-- The three edge functions that walk that list are filtered too, but filters are
-- the half that gets forgotten: there are three of them today and the fourth
-- thing to read `users` will not know it was supposed to. So the rule lives on
-- the row. A keyring entry for a bot is refused by the database, and the three
-- filters become an optimisation rather than the boundary.
--
-- Phase 5 (moderation bots) is the one case that needs the opposite, and it
-- arrives as an explicit per-channel grant — at which point this trigger
-- consults that grant instead of refusing outright. Until then there is no way
-- to key a bot at all, which is the correct amount of ways.

-- ============================================================
-- 1. The flag
-- ============================================================

ALTER TABLE users   ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE invites ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN users.is_bot IS
  'This row is a program, not a person. Set from the invite at registration and '
  'never afterwards — see 014. Bots cannot hold channel keys (channel_keyring '
  'refuses them), and clients list them separately from members.';
COMMENT ON COLUMN invites.is_bot IS
  'This invite mints a bot. Chosen when the invite is created; an ordinary '
  'invite can never produce one.';

CREATE INDEX IF NOT EXISTS idx_users_bots
  ON users (server_id) WHERE is_bot;

-- ============================================================
-- 2. Registration carries it
-- ============================================================
-- Replaces 003's `register_user`. Two changes, both on the last INSERT:
-- `is_bot` comes from the invite, and `can_create_tokens` no longer comes from
-- nowhere.
--
-- That second one is not cosmetic. 003 passed a literal `true`, so every member
-- who ever joined could mint invites regardless of what their invite said. For
-- a person that is a deliberate (if undocumented) openness; for a bot it is a
-- program that can hand out membership of somebody else's server. A bot gets
-- what its invite grants and nothing by default.

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
    is_server_admin, is_channel_manager, can_create_tokens, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager,
    -- A person keeps the old openness; a bot is granted only what was ticked.
    CASE WHEN v_invite.is_bot THEN v_invite.can_create_tokens ELSE true END,
    v_invite.is_bot
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

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_invite.server_id,
    'is_bot', v_invite.is_bot
  );
END; $$;

-- ============================================================
-- 3. `is_bot` is set once, at registration
-- ============================================================
-- Members may UPDATE (display_name, chat_public_key, avatar_path) and nothing
-- else, so no client can write this column today. The trigger is for the paths
-- that are not a client: `set_user_permissions` and `moderate_user` are
-- SECURITY DEFINER and run as the owner, and a future one that does `UPDATE
-- users SET ...` without naming its columns would carry whatever it was handed.
--
-- Turning a person into a bot, or a bot into a person, is not an edit anybody
-- should be able to make — it changes who may hold the keys to a room.

CREATE OR REPLACE FUNCTION pin_is_bot()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  NEW.is_bot := OLD.is_bot;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS users_pin_is_bot ON users;
CREATE TRIGGER users_pin_is_bot BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION pin_is_bot();

-- ============================================================
-- 4. A bot may not be given a channel key
-- ============================================================
-- The boundary, on the row rather than in the three callers that walk past it.
--
-- A trigger rather than a CHECK because the fact lives on another table:
-- `channel_keyring.user_id` → `users.is_bot`. Refusing loudly rather than
-- silently dropping the row, because a client that wrapped a key for a bot
-- believes it did something and would otherwise carry on believing it.

CREATE OR REPLACE FUNCTION refuse_bot_keyring()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RAISE EXCEPTION 'bot_cannot_hold_channel_key';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS channel_keyring_refuse_bots ON channel_keyring;
CREATE TRIGGER channel_keyring_refuse_bots
  BEFORE INSERT OR UPDATE ON channel_keyring
  FOR EACH ROW EXECUTE FUNCTION refuse_bot_keyring();

-- ============================================================
-- 5. Invites that mint bots
-- ============================================================
-- `invites_insert` already carries the delegation rule — you can only grant
-- what you hold — and it is untouched: ticking "this is a bot" is not a
-- permission, so it needs no authority of its own beyond being allowed to make
-- an invite at all.
--
-- What it does need is to be a *decision*. An invite is minted with `is_bot`
-- and cannot be changed afterwards (there is no UPDATE grant on invites), so
-- one link never quietly becomes the other kind.

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (NOT is_server_admin    OR app.is_admin())
    AND (NOT is_channel_manager OR app.can_manage_channels())
    AND (NOT can_create_tokens  OR app.can_invite())
    -- A bot invite may not carry admin. Ending somebody's membership is the
    -- same weight as granting a role, and neither belongs to a program that
    -- joined from a config file. A channel manager bot is a deliberate choice
    -- an operator can still make.
    AND (NOT is_bot OR NOT is_server_admin)
  );
