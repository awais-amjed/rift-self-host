-- ============================================================
-- Rift self-hosted server — 016: no Members role
-- ============================================================
-- Every human was given a role called Members on registration. It carried
-- one bit, `CREATE_INVITE`, and existed so that something could be taken off
-- a person. In practice it was a chip the client had to hide on every row
-- and a rung on the ladder that meant nothing — a role everybody holds is not
-- a role, it is the baseline wearing a name.
--
-- So the baseline carries the bit now, and the role is gone: from the seed,
-- from every server that has it, and from the schema, along with the
-- `is_default` flag that marked it. Inviting is still a permission — a server
-- that wants it narrower takes the bit off `@everyone` and puts it on a role
-- of its own choosing — but the default is open, because a member who cannot
-- bring a friend was never what the default was for.
--
-- A person who registers through an invite that names no role now holds no
-- role at all. That is the correct answer: what they can do is `@everyone`.

-- ============================================================
-- 1. The bit moves, and the role goes
-- ============================================================

UPDATE roles SET permissions = permissions | app.perm('CREATE_INVITE')
 WHERE is_everyone;

-- Cascades to `member_roles`, whose trigger resyncs every holder's cached
-- columns. Then everybody else too: `app.can_invite` reads the cache, and a
-- member holding no role at all — a bot, or somebody the role had been taken
-- off — has just gained the bit from the baseline without any row of theirs
-- changing.
DELETE FROM roles WHERE is_default;
DO $$ BEGIN PERFORM app.sync_permission_cache(id) FROM users; END $$;

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_owner)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('SUMMON_BOTS')   | app.perm('CREATE_INVITE'), true, false),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS')
     | app.perm('CREATE_PRIVATE_CHANNEL'), false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false),
    (NEW.id, 'Owner',     400, app.perm('ADMINISTRATOR'), false, true)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- ============================================================
-- 2. Registration grants only what the invite names
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
    id, server_id, username, display_name, public_key, stable_id, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id, v_invite.is_bot
  );

  -- The role the invite names, if any. Nothing else: the baseline is not
  -- assigned, and there is no default role any more (016).
  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND r.id = v_invite.role_id
     AND NOT r.is_everyone
     AND NOT r.is_owner
  ON CONFLICT DO NOTHING;

  -- The first person in owns the place (013).
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

-- ============================================================
-- 3. The flag goes with it
-- ============================================================
-- The view and the function that pages it both carry the column, so both
-- are remade without it. Same grants as 011 gave them.

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
  END IF;
  RETURN NEW;
END; $$;

DROP FUNCTION IF EXISTS member_roles_for(UUID[]);
DROP VIEW IF EXISTS member_role_list;
ALTER TABLE roles DROP COLUMN IF EXISTS is_default;

CREATE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions,
         r.is_owner
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

COMMENT ON VIEW member_role_list IS
  'Which roles each member holds. `is_owner` marks the one role held by '
  'exactly one person (013).';

REVOKE ALL ON member_role_list FROM anon;
GRANT SELECT ON member_role_list TO authenticated;

CREATE FUNCTION member_roles_for(p_ids UUID[])
  RETURNS SETOF member_role_list
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT l.*
    FROM member_role_list l
   WHERE l.user_id = ANY (COALESCE(p_ids, ARRAY[]::UUID[]))
   ORDER BY l.user_id, l.position DESC
   LIMIT app.member_page_max() * 8
$$;

COMMENT ON FUNCTION member_roles_for(UUID[]) IS
  'Which roles these members hold, most senior first — the chips for the rows '
  'on screen rather than for everybody. Capped at eight roles per member of a '
  'full page; a member wearing more than that has more than a sidebar can show.';

REVOKE ALL ON FUNCTION member_roles_for(UUID[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION member_roles_for(UUID[]) TO authenticated;
