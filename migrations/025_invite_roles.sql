-- ============================================================
-- Rift self-hosted server — 025: an invite carries a role
-- ============================================================
-- The last thing running on the old model. An invite has carried
-- `is_server_admin`, `is_channel_manager` and `can_create_tokens` since 001,
-- and `register_user` turned them into roles at the far end — which worked
-- exactly as long as those three were the only roles there were.
--
-- They are not. A server can make a Moderator role that bans but does not
-- kick, or a Greeter that only mints invites, and there has been no way to
-- write an invite that hands one out. Somebody joins as nothing and waits to
-- be promoted, which for the common case — inviting a person *into* a role —
-- is the whole flow done twice.
--
-- So: one nullable `role_id`, and the three booleans go.
--
-- ---------- what replaces `legacy_key` ----------
--
-- 018 marked the four seeded roles so `set_user_permissions` could find the
-- one a boolean had become. Nothing needs that any more, but one question it
-- was answering still has to be answered: **which role does a person get for
-- simply joining?**
--
-- `@everyone` cannot be it. That one is implicit and applies to bots too, and
-- 014 decided a bot gets invite-minting only if its invite says so — putting
-- `CREATE_INVITE` on `@everyone` would hand every bot the ability to give away
-- membership of somebody else's server.
--
-- `is_default` is that answer, and it says what it means rather than naming
-- what it used to be: the role a *person* is given at registration. Bots skip
-- it, exactly as they always did.

-- ============================================================
-- 1. The role an invite grants
-- ============================================================

ALTER TABLE roles ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS roles_one_default
  ON roles (server_id) WHERE is_default;

COMMENT ON COLUMN roles.is_default IS
  'Granted to a person on registration. Not to a bot: 014 decided a bot holds '
  'only what its invite named.';

UPDATE roles SET is_default = true WHERE legacy_key = 'members';

ALTER TABLE invites
  ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE CASCADE;

COMMENT ON COLUMN invites.role_id IS
  'The role this invite hands out, on top of the default. CASCADE rather than '
  'SET NULL: an invite whose role was deleted would otherwise keep working and '
  'quietly grant nothing, which is worse than a link that stops.';

-- Highest wins, which loses nothing: the only invite that ever set more than
-- one flag is the one `create_server` mints, and `ADMINISTRATOR` implies the
-- other two anyway.
UPDATE invites i SET role_id = r.id
  FROM roles r
 WHERE r.server_id = i.server_id
   AND r.legacy_key = CASE
         WHEN i.is_server_admin    THEN 'admin'
         WHEN i.is_channel_manager THEN 'moderator'
         ELSE NULL
       END;

-- ============================================================
-- 2. You may only invite into a role you could hand out
-- ============================================================
-- 002 wrote this as three lines, one per flag. It is one line now, and it is
-- the same rule the roles editor obeys — which is the point of it being a
-- function rather than a predicate copied into two policies.

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (role_id IS NULL OR app.may_assign_role(role_id))
  );

GRANT INSERT (server_id, created_by, code, max_uses, expires_at, is_bot, role_id)
  ON invites TO authenticated;

-- ============================================================
-- 3. Registration
-- ============================================================
-- Two roles now instead of three booleans: whatever the invite named, plus the
-- server's default for a person.
--
-- The `users` insert no longer writes the three permission columns at all.
-- They have been a cache of three bits since 018, and the only reason
-- registration was still setting them by hand was that it predated the
-- trigger that keeps them.

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
    id, server_id, username, display_name, public_key, stable_id, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id, v_invite.is_bot
  );

  -- The role the invite names, and the one a person gets for turning up. Both
  -- go through the trigger that keeps the three cached columns, so a member
  -- registered this way and one promoted from the roles editor end up
  -- indistinguishable — which they should be.
  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND NOT r.is_everyone
     AND (r.id = v_invite.role_id
          OR (r.is_default AND NOT v_invite.is_bot))
  ON CONFLICT DO NOTHING;

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

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_default)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL'), true, false),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, true),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS'), false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- ============================================================
-- 4. The old model, removed
-- ============================================================

DROP FUNCTION IF EXISTS set_user_permissions(UUID, BOOLEAN, BOOLEAN, BOOLEAN);
DROP FUNCTION IF EXISTS app.apply_legacy_role(UUID, UUID, TEXT, BOOLEAN);

ALTER TABLE invites
  DROP COLUMN IF EXISTS is_server_admin,
  DROP COLUMN IF EXISTS is_channel_manager,
  DROP COLUMN IF EXISTS can_create_tokens;

DROP INDEX IF EXISTS roles_legacy_key;
ALTER TABLE roles DROP COLUMN IF EXISTS legacy_key;
