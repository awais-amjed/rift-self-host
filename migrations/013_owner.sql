-- ============================================================
-- Rift self-hosted server — 013: one owner per server
-- ============================================================
-- Every server has had administrators since 006 and nobody who could end it.
-- Admins are equals: each can hand out the Admin role, none can take it off
-- another, and there was no role a server could not be left without. Two
-- questions had no answer as a result — who may delete a server, and who
-- decides when the person running it steps down.
--
-- The answer is a fifth seeded role, `Owner`, and it is different in kind from
-- the other four. There is exactly one of it per server, exactly one person
-- holds it, and nobody hands it out: it goes to the first person who joins —
-- whoever redeemed the invite the console printed at setup — and moves only
-- through `transfer_ownership`, which the owner alone can call. The old owner
-- stays an admin. Everything an owner can do beyond an admin is here: delete
-- the server, and pass it on.
--
-- ---------- why a role rather than a column ----------
--
-- `servers.owner_id` would have been shorter. It would also have been a second
-- ladder: every delegation rule since 006 is decided on role position and
-- nothing else, and a column would need its own "outranks everyone" clause in
-- every policy that already has one. As a role at position 400 the owner
-- outranks admins (300) by the rule that already exists, may edit and hand out
-- every role beneath, and cannot be edited, kicked, banned or demoted by
-- anybody — because nothing stands above 400.
--
-- What a role cannot do on its own is stay singular and stay out of the
-- editor, which is the whole of what this file adds.


-- ============================================================
-- 1. The role
-- ============================================================

ALTER TABLE roles ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT false;

-- One per server. The seed below makes it, and the trigger under it keeps it.
CREATE UNIQUE INDEX IF NOT EXISTS roles_one_owner
  ON roles (server_id) WHERE is_owner;

-- Not editable, not deletable, not movable. Position 400 is what outranks an
-- admin, and `ADMINISTRATOR` is what makes rank mean anything; both are pinned
-- rather than policed so that even the service role cannot half-break it.
-- The one delete that goes through is the cascade from the server's own row.
CREATE OR REPLACE FUNCTION protect_owner_role()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.is_owner AND EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id) THEN
      RAISE EXCEPTION 'owner_is_permanent';
    END IF;
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    NEW.is_owner := OLD.is_owner;
  END IF;
  IF NEW.is_owner THEN
    NEW.position    := 400;
    NEW.permissions := app.perm('ADMINISTRATOR');
    NEW.is_everyone := false;
    NEW.is_default  := false;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS roles_protect_owner ON roles;
CREATE TRIGGER roles_protect_owner BEFORE INSERT OR UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION protect_owner_role();

-- The baseline's guard from 006 needs the same exception. Nothing deleted a
-- server until now, so nothing had noticed that the cascade could not get past
-- `@everyone`.
CREATE OR REPLACE FUNCTION protect_everyone_role()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.is_everyone AND EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id) THEN
      RAISE EXCEPTION 'everyone_is_permanent';
    END IF;
    RETURN OLD;
  END IF;
  NEW.is_everyone := OLD.is_everyone;
  IF NEW.is_everyone THEN NEW.position := 0; END IF;
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_default, is_owner)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL')
     | app.perm('SUMMON_BOTS'), true, false, false),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, true, false),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS'), false, false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false, false),
    (NEW.id, 'Owner',     400, app.perm('ADMINISTRATOR'), false, false, true)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- The servers that already exist.
INSERT INTO roles (server_id, name, position, permissions, is_owner)
SELECT s.id, 'Owner', 400, app.perm('ADMINISTRATOR'), true
  FROM servers s
 WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.server_id = s.id AND r.is_owner)
ON CONFLICT (server_id, name) DO NOTHING;


-- ============================================================
-- 2. Who holds it
-- ============================================================
-- Nobody hands it out. `may_assign_role` is what every write to
-- `member_roles` and every `invites.role_id` asks, so refusing the owner role
-- there closes both doors at once — an admin's own-rank exemption included,
-- since that clause was written for the only admin making a second one.

CREATE OR REPLACE FUNCTION app.may_assign_role(p_role UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('MANAGE_ROLES')
     AND EXISTS (
       SELECT 1 FROM roles r
        WHERE r.id = p_role
          AND r.server_id = app.server_id()
          AND NOT r.is_everyone
          AND NOT r.is_owner
          AND (app.has_perm('ADMINISTRATOR')
               OR r.position < app.max_role_position()))
$$;

-- The two paths that do grant it — registration and transfer — run as the
-- service role or as definer, past every policy. This is what keeps them
-- honest: one holder, and never a bot, whichever path wrote the row.
CREATE OR REPLACE FUNCTION refuse_second_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.is_owner) THEN
    RETURN NEW;
  END IF;
  IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RAISE EXCEPTION 'bot_cannot_own';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles mr
              WHERE mr.role_id = NEW.role_id AND mr.user_id <> NEW.user_id) THEN
    RAISE EXCEPTION 'owner_is_singular';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS member_roles_refuse_second_owner ON member_roles;
CREATE TRIGGER member_roles_refuse_second_owner BEFORE INSERT OR UPDATE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION refuse_second_owner();

-- An owner does not leave; they transfer or delete. Without this a server
-- could end up with nobody who can do either, which is the state this whole
-- file exists to make impossible. The server being deleted is the exception:
-- its rows go with it, owner first or last.
CREATE OR REPLACE FUNCTION refuse_owner_leaving()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id)
     AND EXISTS (SELECT 1 FROM member_roles mr
                   JOIN roles r ON r.id = mr.role_id
                  WHERE mr.user_id = OLD.id AND r.is_owner) THEN
    RAISE EXCEPTION 'owner_cannot_leave';
  END IF;
  RETURN OLD;
END; $$;

DROP TRIGGER IF EXISTS users_refuse_owner_leaving ON users;
CREATE TRIGGER users_refuse_owner_leaving BEFORE DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION refuse_owner_leaving();


-- ============================================================
-- 3. A cached answer, beside the other three
-- ============================================================
-- Clients read `is_server_admin` off their own row to decide what to offer;
-- "am I the owner" is the same kind of question and gets the same kind of
-- answer, kept by the same trigger.

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION app.sync_permission_cache(p_user UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bits BIGINT;
  v_admin BIGINT := app.perm('ADMINISTRATOR');
BEGIN
  v_bits := app.permissions_of(p_user);
  UPDATE users SET
    is_server_admin    = (v_bits & v_admin) <> 0,
    is_channel_manager = (v_bits & (v_admin | app.perm('MANAGE_CHANNELS'))) <> 0,
    can_create_tokens  = (v_bits & (v_admin | app.perm('CREATE_INVITE'))) <> 0,
    is_owner           = EXISTS (SELECT 1 FROM member_roles mr
                                   JOIN roles r ON r.id = mr.role_id
                                  WHERE mr.user_id = p_user AND r.is_owner)
   WHERE id = p_user;
END; $$;

CREATE OR REPLACE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions,
         r.is_default,
         r.is_owner
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

REVOKE ALL ON member_role_list FROM anon;
GRANT SELECT ON member_role_list TO authenticated;


-- ============================================================
-- 4. The first person in
-- ============================================================
-- Registration already grants the invite's role and the default one. Now it
-- also grants ownership to the first human on a server that has no owner —
-- which, on a server the console just provisioned, is whoever redeemed the
-- setup invite. `refuse_second_owner` makes "no owner yet" the only case that
-- can succeed, so this is not a race two people can both win.

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

  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND NOT r.is_everyone
     AND NOT r.is_owner
     AND (r.id = v_invite.role_id
          OR (r.is_default AND NOT v_invite.is_bot))
  ON CONFLICT DO NOTHING;

  IF NOT v_invite.is_bot AND NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE r.server_id = v_invite.server_id AND r.is_owner) THEN
    INSERT INTO member_roles (user_id, role_id)
    SELECT p_user_id, r.id FROM roles r
     WHERE r.server_id = v_invite.server_id AND r.is_owner;
  END IF;

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

-- The servers that already have members: the longest-standing admin, or
-- failing that the longest-standing person, is the owner from here on.
INSERT INTO member_roles (user_id, role_id)
SELECT DISTINCT ON (r.server_id) u.id, r.id
  FROM roles r
  JOIN users u ON u.server_id = r.server_id AND NOT u.is_bot AND NOT u.is_banned
 WHERE r.is_owner
   AND NOT EXISTS (SELECT 1 FROM member_roles mr WHERE mr.role_id = r.id)
 ORDER BY r.server_id, u.is_server_admin DESC, u.created_at, u.id
ON CONFLICT DO NOTHING;

-- Members whose rows predate the cached column, owner or not.
DO $$ BEGIN PERFORM app.sync_permission_cache(id) FROM users; END $$;


-- ============================================================
-- 5. Passing it on
-- ============================================================
-- The one write that moves the owner role. Definer, because the policies
-- refuse this role in both directions and should keep doing so; the checks
-- the policies would have made are made here instead, in the order that
-- leaves the server with exactly one owner whichever line raises.

CREATE OR REPLACE FUNCTION transfer_ownership(p_user UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_role   UUID;
  v_target users%ROWTYPE;
BEGIN
  SELECT r.id INTO v_role
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id
   WHERE mr.user_id = auth.uid() AND r.is_owner;
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'not_owner';
  END IF;

  SELECT * INTO v_target FROM users
   WHERE id = p_user AND server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  IF v_target.id = auth.uid() THEN
    RAISE EXCEPTION 'cannot_transfer_to_self';
  END IF;
  IF v_target.is_bot THEN
    RAISE EXCEPTION 'bot_cannot_own';
  END IF;
  IF v_target.is_banned THEN
    RAISE EXCEPTION 'user_banned';
  END IF;

  DELETE FROM member_roles WHERE user_id = auth.uid() AND role_id = v_role;
  INSERT INTO member_roles (user_id, role_id, granted_by)
  VALUES (p_user, v_role, auth.uid());

  -- Stepping down from owner, not from running the place: the most senior
  -- role beneath that still carries `ADMINISTRATOR`, if the server has one.
  INSERT INTO member_roles (user_id, role_id, granted_by)
  SELECT auth.uid(), r.id, auth.uid()
    FROM roles r
   WHERE r.server_id = app.server_id()
     AND NOT r.is_owner AND NOT r.is_everyone
     AND (r.permissions & app.perm('ADMINISTRATOR')) <> 0
   ORDER BY r.position DESC
   LIMIT 1
  ON CONFLICT DO NOTHING;
END; $$;

REVOKE ALL ON FUNCTION transfer_ownership(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION transfer_ownership(UUID) TO authenticated;


-- ============================================================
-- 6. Ending it
-- ============================================================
-- The row delete cascades to everything the server holds. What it cannot
-- reach — the LiveKit rooms and the storage buckets — the `delete_server`
-- edge function clears with the service role, after this has said yes.
-- Authority stays here: the function is the gate, the edge function is the
-- broom.

CREATE OR REPLACE FUNCTION delete_server() RETURNS UUID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL OR NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE mr.user_id = auth.uid() AND r.is_owner AND r.server_id = v_server) THEN
    RAISE EXCEPTION 'not_owner';
  END IF;
  DELETE FROM servers WHERE id = v_server;
  RETURN v_server;
END; $$;

REVOKE ALL ON FUNCTION delete_server() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delete_server() TO authenticated;
