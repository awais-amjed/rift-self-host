-- ============================================================
-- Rift self-hosted server — 008: Managing roles safely
-- ============================================================
-- The rules that stop a role edit locking somebody out of their own server —
-- spacing, invite roles, no self-demotion, and restoring the last admin.
--
-- Was 4 files: 024_role_spacing, 025_invite_roles, 026_no_self_demotion, 027_restore_admins.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 024: leaving room between roles
-- ============================================================
-- 018 seeded the four default roles at 0, 1, 2 and 3, which is the tidiest
-- possible ladder and the one with nowhere to stand. Rank is what every
-- delegation rule is decided on — you may only touch a role strictly below
-- your own — so an admin at rank 3 has exactly two rungs beneath them, and the
-- third custom role has to share a rung with the second.
--
-- Two roles at the same position is not a correctness problem: neither can
-- manage the other, which is the conservative answer. It is an *ordering*
-- problem — a list sorted by position cannot say which of them is senior, and
-- neither can a reorder that works by swapping positions.
--
-- So the rungs are spaced. Nothing about the rules changes; there is simply
-- room between them for the roles a server actually invents.

UPDATE roles SET position = CASE legacy_key
  WHEN 'admin'     THEN 300
  WHEN 'moderator' THEN 200
  WHEN 'members'   THEN 100
END
WHERE legacy_key IS NOT NULL;

-- Anything already sitting above `@everyone` and below the old Admin rung is
-- lifted onto the same scale, keeping its order. A server that has never made
-- a custom role has nothing here to move.
WITH ranked AS (
  SELECT id,
         row_number() OVER (PARTITION BY server_id ORDER BY position, created_at)
           AS rung
    FROM roles
   WHERE legacy_key IS NULL AND NOT is_everyone AND position < 300
)
UPDATE roles r SET position = ranked.rung * 10
  FROM ranked WHERE ranked.id = r.id;

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, legacy_key)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL'), true, NULL),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, 'members'),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS'), false, 'moderator'),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, 'admin')
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;


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


-- ============================================================
-- Rift self-hosted server — 026: an admin cannot lock themselves out
-- ============================================================
-- 018 exempted `ADMINISTRATOR` from the position rule when *handing out* a
-- role, for a good reason: without it the only admin on a server could never
-- make a second one, and `set_user_permissions` had allowed exactly that since
-- 003.
--
-- The exemption was written once and applied to both directions. So an admin
-- could also take the Admin role *off* — including off themselves, leaving a
-- server with no administrator and no way to appoint one. The old RPC refused
-- that by name (`cannot_change_own_permissions`); moving to roles dropped the
-- refusal along with the function.
--
-- Found by a test that had been asserting the old function's behaviour and was
-- rewritten to assert the new model's.
--
-- The rule that replaces it: **you may not take a role off yourself unless you
-- outrank it.** Which for your own highest role you never do.
--
-- Deliberately not "you may not remove Admin". Two admins can still demote each
-- other, which is the check on a rogue one, and it is the same shape as every
-- other rule here — position, and nothing else.

DROP POLICY IF EXISTS member_roles_delete ON member_roles;
CREATE POLICY member_roles_delete ON member_roles FOR DELETE TO authenticated
  USING (
    app.may_assign_role(role_id)
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
    -- Somebody else's, or one you genuinely stand above.
    AND (member_roles.user_id <> auth.uid()
         OR EXISTS (SELECT 1 FROM roles r
                     WHERE r.id = member_roles.role_id
                       AND r.position < app.max_role_position()))
  );


-- ============================================================
-- Rift self-hosted server — 027: giving back the admins 018 took
-- ============================================================
-- 018 created the four default roles and then read `users.is_server_admin` to
-- decide who should hold them. Between those two steps its own trigger fired:
-- inserting `@everyone` runs `roles_sync_cache`, which recomputes all three
-- cached booleans from the roles a member holds — none, at that instant — and
-- writes `false` over every one of them.
--
-- So the backfill read an empty server and granted nobody anything. Every
-- server it ran on came out with no administrator, and no way to appoint one:
-- handing out a role needs `MANAGE_ROLES`, which nobody had any more.
--
-- 018 is fixed at the source — it snapshots the columns before it touches
-- anything — so a database migrated from here forward never sees this. This is
-- for the ones already past it, where the original values are gone and cannot
-- be read back out of anything.
--
-- ---------- what it does, and why the guard matters ----------
--
-- There is no record left of who was an admin, so this cannot restore the
-- answer. It restores *an* answer: the earliest member of a server, who on
-- every server Rift has ever made is whoever created it — `create_server`
-- mints a single-use admin invite and hands it to them before anybody else can
-- join.
--
-- It only acts on a server with **no administrator at all**, which after 018's
-- fix is a state a database can only reach by having run the broken version.
-- A server with even one admin is left alone: this is a repair, not a policy,
-- and a repair that ran twice would be a back door.

DO $restore$
DECLARE
  v_server  UUID;
  v_admin   UUID;
  v_oldest  UUID;
BEGIN
  FOR v_server IN
    SELECT s.id FROM servers s
     WHERE NOT EXISTS (
       SELECT 1 FROM users u
         JOIN member_roles mr ON mr.user_id = u.id
         JOIN roles r         ON r.id = mr.role_id
        WHERE u.server_id = s.id
          AND (r.permissions & app.perm('ADMINISTRATOR')) <> 0)
  LOOP
    SELECT id INTO v_admin FROM roles
     WHERE server_id = v_server
       AND (permissions & app.perm('ADMINISTRATOR')) <> 0
     ORDER BY position DESC LIMIT 1;
    CONTINUE WHEN v_admin IS NULL;

    -- A bot is never the answer. It cannot hold a channel key, and a server
    -- administered by a program nobody can log in as is not a repair.
    SELECT id INTO v_oldest FROM users
     WHERE server_id = v_server AND NOT is_bot AND NOT is_banned
     ORDER BY created_at, id LIMIT 1;
    CONTINUE WHEN v_oldest IS NULL;

    INSERT INTO member_roles (user_id, role_id)
    VALUES (v_oldest, v_admin)
    ON CONFLICT DO NOTHING;
  END LOOP;
END $restore$;

-- The same trigger, the same omission: 018 read `can_create_tokens` to decide
-- who got `Members`, and that column had been zeroed too. Every person on a
-- server holds the default role — that is what `is_default` means — so this
-- one needs no guard and no heuristic.
INSERT INTO member_roles (user_id, role_id)
SELECT u.id, r.id
  FROM users u
  JOIN roles r ON r.server_id = u.server_id AND r.is_default
 WHERE NOT u.is_bot
ON CONFLICT DO NOTHING;
