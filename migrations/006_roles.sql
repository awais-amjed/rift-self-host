-- ============================================================
-- Rift self-hosted server — 006: Roles and permissions
-- ============================================================
-- Named roles with positions, replacing the three booleans that came before.
--
-- Was 1 file: 018_roles.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 018: roles and granular permissions
-- ============================================================
-- Three booleans have carried every authority decision on a server so far:
-- `is_server_admin`, `is_channel_manager`, `can_create_tokens`. They were the
-- right size while there were three things to decide. There are now nineteen,
-- and private channels (019) add the one that cannot be a boolean at all.
--
-- So: named permission bits, roles that carry a set of them, and members that
-- carry roles.
--
-- ---------- what does not change ----------
--
-- The three columns stay, and every policy that reads them keeps working. They
-- are no longer *written* by anything — they become a cache of three bits,
-- kept by a trigger. That is what makes this migration safe to apply to a
-- running server: the truth moves to `roles` and every existing caller carries
-- on reading the same column it always read.
--
-- ---------- the one rule that is not like Discord's ----------
--
-- `VIEW_CHANNEL` is not enforced, it is **arithmetic**. Everywhere else a
-- permission is a rule the database applies to a request; for a channel key it
-- is a list of people something was sealed to. A rule can be changed and takes
-- effect at once. A sealed key cannot be taken back — it can only be made
-- useless by rotating past it.
--
-- That is why `VIEW_CHANNEL` resolves to a set of *people* and why 019 spends
-- a whole migration on it, while the other eighteen bits are a `WHERE` clause.
--
-- ---------- delegation ----------
--
-- 002 wrote the rule as three lines on `invites_insert`: you may only grant a
-- flag you hold. With nineteen bits and custom roles that becomes two rules,
-- and both live here rather than in the clients:
--
--   1. **Position.** You may only touch a role ranked below your own highest.
--      Without it, `MANAGE_ROLES` is `ADMINISTRATOR` with extra steps — grant
--      yourself admin, or edit the admin role.
--   2. **Subset.** The permissions you put on a role must be ones you hold.
--      Without it, position alone lets you mint a role below you that can do
--      more than you can.
--
-- `ADMINISTRATOR` is exempt from the subset rule because it holds everything
-- by definition, and from position by being the top.

-- ============================================================
-- 0. What the three booleans said, before this file touches anything
-- ============================================================
-- The backfill in §5 reads these columns to work out who held what. It cannot
-- read them off `users` by the time it runs: creating the `@everyone` role in
-- that same block fires `roles_sync_cache`, which recomputes all three from
-- the roles a member holds — none, yet — and writes `false` over every one of
-- them. The backfill then finds an empty server and grants nobody anything.
--
-- Every admin on every server, silently, in the migration that was supposed to
-- preserve them. The snapshot is taken here, before the tables and triggers in
-- §2 and §4 exist at all, and §5 reads it instead.

DROP TABLE IF EXISTS legacy_user_permissions;
CREATE TEMP TABLE legacy_user_permissions AS
  SELECT id, server_id, is_server_admin, is_channel_manager, can_create_tokens
    FROM users;

-- ============================================================
-- 1. The permission set
-- ============================================================
-- Named rather than numbered at the call site: `app.has_perm('BAN_MEMBERS')`
-- says what it wants, and a policy is read far more often than it is written.
--
-- The bit numbers are the contract — the app and any future SDK share this
-- list — so they are assigned once and never reused. A permission that is
-- retired leaves its bit vacant.
--
CREATE OR REPLACE FUNCTION app.perm_bit(p_name TEXT) RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_name
    -- Server
    WHEN 'ADMINISTRATOR'   THEN 1::BIGINT << 0   -- implies every other bit
    WHEN 'MANAGE_SERVER'   THEN 1::BIGINT << 1
    WHEN 'MANAGE_ROLES'    THEN 1::BIGINT << 2
    WHEN 'MANAGE_CHANNELS' THEN 1::BIGINT << 3
    WHEN 'CREATE_INVITE'   THEN 1::BIGINT << 4
    WHEN 'KICK_MEMBERS'    THEN 1::BIGINT << 5
    WHEN 'BAN_MEMBERS'     THEN 1::BIGINT << 6
    WHEN 'MANAGE_BOTS'     THEN 1::BIGINT << 7   -- the §6 channel-key grant
    WHEN 'MANAGE_WEBHOOKS' THEN 1::BIGINT << 8
    -- Text
    WHEN 'VIEW_CHANNEL'    THEN 1::BIGINT << 9   -- see §019; cryptographic
    WHEN 'SEND_MESSAGES'   THEN 1::BIGINT << 10
    WHEN 'ATTACH_FILES'    THEN 1::BIGINT << 11
    WHEN 'ADD_REACTIONS'   THEN 1::BIGINT << 12
    WHEN 'MENTION_ALL'     THEN 1::BIGINT << 13
    WHEN 'MANAGE_MESSAGES' THEN 1::BIGINT << 14  -- delete anybody's
    -- Voice
    WHEN 'CONNECT'         THEN 1::BIGINT << 15
    WHEN 'SPEAK'           THEN 1::BIGINT << 16
    WHEN 'SCREEN_SHARE'    THEN 1::BIGINT << 17
    WHEN 'MUTE_MEMBERS'    THEN 1::BIGINT << 18
    WHEN 'DEAFEN_MEMBERS'  THEN 1::BIGINT << 19
    WHEN 'MOVE_MEMBERS'    THEN 1::BIGINT << 20
  END
$$;

-- The one callers use. `perm_bit` returns NULL for a name it does not know, and
-- NULL propagates through every `&` and `|` below into a policy that quietly
-- denies everything — which reads exactly like a working policy until it is the
-- only thing between somebody and a room they should not be in. So the lookup
-- that policies call refuses instead.
CREATE OR REPLACE FUNCTION app.perm(p_name TEXT) RETURNS BIGINT
  LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v_bit BIGINT;
BEGIN
  v_bit := app.perm_bit(p_name);
  IF v_bit IS NULL THEN
    RAISE EXCEPTION 'unknown permission: %', p_name;
  END IF;
  RETURN v_bit;
END; $$;

-- Everything a role can hold, for the subset rule and for `ADMINISTRATOR`.
CREATE OR REPLACE FUNCTION app.perm_all() RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$ SELECT (1::BIGINT << 21) - 1 $$;

-- ============================================================
-- 2. Roles
-- ============================================================

CREATE TABLE IF NOT EXISTS roles (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id    UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name         TEXT        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 40),
  -- Hex, or null for "no colour" — a role that exists to carry permissions
  -- rather than to be seen.
  color        TEXT        CHECK (color IS NULL OR color ~ '^#[0-9A-Fa-f]{6}$'),
  -- Higher is more senior. Delegation is decided on this and nothing else, so
  -- it is not a display preference.
  position     INTEGER     NOT NULL DEFAULT 1 CHECK (position >= 0),
  permissions  BIGINT      NOT NULL DEFAULT 0,
  -- The implicit baseline every member has. Never assigned, never deleted,
  -- always position 0.
  is_everyone  BOOLEAN     NOT NULL DEFAULT false,
  UNIQUE (server_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS roles_one_everyone
  ON roles (server_id) WHERE is_everyone;

CREATE INDEX IF NOT EXISTS roles_server ON roles (server_id, position DESC);

COMMENT ON TABLE roles IS
  'A named set of permission bits (app.perm). `is_everyone` is the implicit '
  'baseline: it is never in member_roles and cannot be deleted.';

CREATE TABLE IF NOT EXISTS member_roles (
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS member_roles_role ON member_roles (role_id);

-- `@everyone` is implicit, so a row naming it would be a second answer to a
-- question that already has one — and the two would drift.
CREATE OR REPLACE FUNCTION refuse_everyone_assignment()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.is_everyone) THEN
    RAISE EXCEPTION 'everyone_is_implicit';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS member_roles_refuse_everyone ON member_roles;
CREATE TRIGGER member_roles_refuse_everyone BEFORE INSERT OR UPDATE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION refuse_everyone_assignment();

CREATE OR REPLACE FUNCTION protect_everyone_role()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.is_everyone THEN RAISE EXCEPTION 'everyone_is_permanent'; END IF;
    RETURN OLD;
  END IF;
  -- Neither direction: a role cannot become the baseline, and the baseline
  -- cannot stop being it or move off the bottom.
  NEW.is_everyone := OLD.is_everyone;
  IF NEW.is_everyone THEN NEW.position := 0; END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS roles_protect_everyone ON roles;
CREATE TRIGGER roles_protect_everyone BEFORE UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION protect_everyone_role();

-- A transition column, and marked as one. The app still says "make this person
-- a channel manager", and `set_user_permissions` still has that signature; both
-- need to find the role that used to be a boolean. Matching on name breaks the
-- moment somebody renames it and matching on bits is ambiguous the moment two
-- roles hold the same ones.
--
-- Drops when the roles UI lands and nothing asks for a boolean any more.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS legacy_key TEXT
  CHECK (legacy_key IN ('admin', 'moderator', 'members'));

CREATE UNIQUE INDEX IF NOT EXISTS roles_legacy_key
  ON roles (server_id, legacy_key) WHERE legacy_key IS NOT NULL;

-- ============================================================
-- 3. Effective permissions
-- ============================================================
-- The baseline plus every assigned role, OR'd. `@everyone` is folded in here
-- rather than assigned, which is why it needs no rows and cannot drift.

CREATE OR REPLACE FUNCTION app.permissions_of(p_user UUID) RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((
    SELECT bit_or(r.permissions)
      FROM users u
      JOIN roles r ON r.server_id = u.server_id
     WHERE u.id = p_user
       AND NOT u.is_banned
       AND (r.is_everyone
            OR EXISTS (SELECT 1 FROM member_roles mr
                        WHERE mr.role_id = r.id AND mr.user_id = u.id))
  ), 0)
$$;

CREATE OR REPLACE FUNCTION app.permissions() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.permissions_of(auth.uid())
$$;

-- `ADMINISTRATOR` implies everything, so it is folded into the mask rather
-- than checked separately — one `&` instead of a branch every caller repeats.
CREATE OR REPLACE FUNCTION app.has_perm(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.permissions() & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

-- Delegation rank: the highest position among the roles actually assigned to
-- you. `@everyone` is position 0 and never assigned, so somebody with no roles
-- ranks 0 and can touch nothing — which is the correct answer.
CREATE OR REPLACE FUNCTION app.max_role_position() RETURNS INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((
    SELECT max(r.position)
      FROM member_roles mr
      JOIN roles r ON r.id = mr.role_id
     WHERE mr.user_id = auth.uid()
  ), 0)
$$;

-- May I create, edit, delete or hand out this role?
--
-- Strictly below, including for an administrator. Two admins holding the same
-- role cannot edit it out from under each other, and nobody can raise their own
-- rank — the alternative is that `MANAGE_ROLES` is `ADMINISTRATOR` with extra
-- steps.
CREATE OR REPLACE FUNCTION app.may_manage_role(p_position INTEGER) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('MANAGE_ROLES') AND p_position < app.max_role_position()
$$;

-- ============================================================
-- 4. The three booleans become a cache
-- ============================================================
-- Nothing writes them any more; a trigger keeps them equal to three bits. Every
-- policy, function and edge function that reads `is_server_admin` keeps working
-- unchanged, which is the whole reason this migration can be applied without
-- touching them.
--
-- Derived from the *bits*, not from the backfilled role names — a custom role
-- carrying `MANAGE_CHANNELS` makes its holder a channel manager, which is what
-- granular permissions were for.

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
    can_create_tokens  = (v_bits & (v_admin | app.perm('CREATE_INVITE'))) <> 0
   WHERE id = p_user;
END; $$;

CREATE OR REPLACE FUNCTION sync_member_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    PERFORM app.sync_permission_cache(OLD.user_id);
  END IF;
  IF TG_OP <> 'DELETE' THEN
    PERFORM app.sync_permission_cache(NEW.user_id);
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS member_roles_sync_cache ON member_roles;
CREATE TRIGGER member_roles_sync_cache
  AFTER INSERT OR UPDATE OR DELETE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION sync_member_permission_cache();

-- Editing a role's permissions moves everybody holding it, and editing
-- `@everyone` moves the whole server.
CREATE OR REPLACE FUNCTION sync_role_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_role roles%ROWTYPE;
BEGIN
  -- Branch rather than COALESCE: on DELETE there is no NEW, and a composite
  -- COALESCE over an unassigned record is not something to find out about in
  -- production.
  IF TG_OP = 'DELETE' THEN v_role := OLD; ELSE v_role := NEW; END IF;

  IF v_role.is_everyone THEN
    PERFORM app.sync_permission_cache(u.id)
       FROM users u WHERE u.server_id = v_role.server_id;
  ELSE
    PERFORM app.sync_permission_cache(mr.user_id)
       FROM member_roles mr WHERE mr.role_id = v_role.id;
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS roles_sync_cache ON roles;
CREATE TRIGGER roles_sync_cache AFTER INSERT OR UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION sync_role_permission_cache();

-- Handing out a role is not the same act as editing one.
--
-- Editing is strictly-below for everybody, administrators included: nobody
-- rewrites the role they themselves hold. Assigning is strictly-below too,
-- except for an administrator — otherwise the only admin on a server could
-- never make a second one, and `set_user_permissions` has let them do exactly
-- that since 003. Editing the admin role is meaningless anyway; `ADMINISTRATOR`
-- already implies every bit there is.
CREATE OR REPLACE FUNCTION app.may_assign_role(p_role UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('MANAGE_ROLES')
     AND EXISTS (
       SELECT 1 FROM roles r
        WHERE r.id = p_role
          AND r.server_id = app.server_id()
          AND NOT r.is_everyone
          AND (app.has_perm('ADMINISTRATOR')
               OR r.position < app.max_role_position()))
$$;

-- The subset rule: you cannot put a permission on a role that you do not hold
-- yourself. Without it, position alone lets somebody mint a role beneath them
-- that outranks them in every way that matters.
CREATE OR REPLACE FUNCTION app.may_hold_perms(p_bits BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR') OR (p_bits & ~app.permissions()) = 0
$$;

-- ============================================================
-- 5. Backfill
-- ============================================================
-- Four roles per server, reproducing exactly what the three booleans meant.
-- Idempotent, and reading the §0 snapshot rather than the live columns —
-- which by now say nothing, because creating `@everyone` above has already
-- recomputed every one of them from a member's roles, and nobody has any yet.
--
--   @everyone   what every member could always do, bots included
--   Members     CREATE_INVITE — a person got this on joining (014); a bot only
--               if its invite said so, which is why it is not on @everyone
--   Moderator   `is_channel_manager`: channels, messages, webhooks, kick, and
--               the voice moderation it already had (003's `moderate_user`)
--   Admin       `is_server_admin`

DO $backfill$
DECLARE
  v_server servers%ROWTYPE;
  v_everyone BIGINT;
  v_moderator BIGINT;
BEGIN
  v_everyone :=
      app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
    | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
    -- Nobody has ever been stopped from `@all`; taking it away here would be a
    -- silent behaviour change wearing a migration's clothes. It is a bit now,
    -- so a server that wants it gone can take it.
    | app.perm('MENTION_ALL')
    | app.perm('CONNECT')       | app.perm('SPEAK')
    | app.perm('SCREEN_SHARE');

  v_moderator :=
      app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
    | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
    | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
    | app.perm('MOVE_MEMBERS');

  FOR v_server IN SELECT * FROM servers LOOP
    INSERT INTO roles (server_id, name, position, permissions, is_everyone, legacy_key)
    VALUES
      (v_server.id, '@everyone', 0, v_everyone,                    true,  NULL),
      (v_server.id, 'Members',   1, app.perm('CREATE_INVITE'),     false, 'members'),
      (v_server.id, 'Moderator', 2, v_moderator,                   false, 'moderator'),
      (v_server.id, 'Admin',     3, app.perm('ADMINISTRATOR'),     false, 'admin')
    ON CONFLICT (server_id, name) DO NOTHING;

    INSERT INTO member_roles (user_id, role_id)
    SELECT u.id, r.id
      FROM legacy_user_permissions u
      JOIN roles r ON r.server_id = u.server_id AND r.legacy_key IS NOT NULL
     WHERE u.server_id = v_server.id
       AND ((r.legacy_key = 'admin'     AND u.is_server_admin)
         OR (r.legacy_key = 'moderator' AND u.is_channel_manager)
         OR (r.legacy_key = 'members'   AND u.can_create_tokens))
    ON CONFLICT DO NOTHING;
  END LOOP;
END $backfill$;

DROP TABLE legacy_user_permissions;

-- A server created after this migration needs its four roles too, and the one
-- place that knows a server was created is the row appearing.
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
     | app.perm('SCREEN_SHARE'), true, NULL),
    (NEW.id, 'Members',   1, app.perm('CREATE_INVITE'), false, 'members'),
    (NEW.id, 'Moderator', 2,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS'), false, 'moderator'),
    (NEW.id, 'Admin',     3, app.perm('ADMINISTRATOR'), false, 'admin')
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS servers_seed_roles ON servers;
CREATE TRIGGER servers_seed_roles AFTER INSERT ON servers
  FOR EACH ROW EXECUTE FUNCTION seed_default_roles();

-- ============================================================
-- 6. The two writers move to roles
-- ============================================================
-- `set_user_permissions` keeps its name, its signature and its authority. Only
-- what it writes changes: three role memberships instead of three columns, and
-- the trigger puts the columns back. The client that calls it does not know
-- anything happened, which is the point — the roles UI can land later without
-- a flag day.

CREATE OR REPLACE FUNCTION set_user_permissions(
  p_target             UUID,
  p_is_server_admin    BOOLEAN DEFAULT NULL,
  p_is_channel_manager BOOLEAN DEFAULT NULL,
  p_can_create_tokens  BOOLEAN DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
BEGIN
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF p_target = auth.uid() THEN
    RAISE EXCEPTION 'cannot_change_own_permissions';
  END IF;
  SELECT server_id INTO v_server FROM users
   WHERE id = p_target AND server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;

  -- NULL still means "leave it alone", so each flag is two statements rather
  -- than one upsert: nothing happens for the ones that were not named.
  PERFORM app.apply_legacy_role(p_target, v_server, 'admin',     p_is_server_admin);
  PERFORM app.apply_legacy_role(p_target, v_server, 'moderator', p_is_channel_manager);
  PERFORM app.apply_legacy_role(p_target, v_server, 'members',   p_can_create_tokens);

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION app.apply_legacy_role(
  p_user   UUID,
  p_server UUID,
  p_key    TEXT,
  p_on     BOOLEAN
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_role UUID;
BEGIN
  IF p_on IS NULL THEN RETURN; END IF;
  SELECT id INTO v_role FROM roles
   WHERE server_id = p_server AND legacy_key = p_key;
  IF NOT FOUND THEN RETURN; END IF;

  IF p_on THEN
    INSERT INTO member_roles (user_id, role_id, granted_by)
    VALUES (p_user, v_role, auth.uid())
    ON CONFLICT DO NOTHING;
  ELSE
    DELETE FROM member_roles WHERE user_id = p_user AND role_id = v_role;
  END IF;
END; $$;

-- `register_user` gains four lines. The `users` INSERT still carries the three
-- booleans, and that is not redundant: the role assignment recomputes them to
-- the same values, and a server that somehow has no default roles still ends up
-- with a member whose permissions match their invite.
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
  v_tokens BOOLEAN;
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

  -- A person keeps the old openness; a bot is granted only what was ticked.
  v_tokens := CASE WHEN v_invite.is_bot THEN v_invite.can_create_tokens ELSE true END;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager, v_tokens,
    v_invite.is_bot
  );

  PERFORM app.apply_legacy_role(p_user_id, v_invite.server_id, 'admin',
                                v_invite.is_server_admin);
  PERFORM app.apply_legacy_role(p_user_id, v_invite.server_id, 'moderator',
                                v_invite.is_channel_manager);
  PERFORM app.apply_legacy_role(p_user_id, v_invite.server_id, 'members', v_tokens);

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
-- 7. Security
-- ============================================================
-- New tables in `public` arrive writable by `authenticated`, and new functions
-- arrive executable by PUBLIC. Both are revoked by name here; a table added
-- without this is one an ordinary member can rewrite.

ALTER TABLE roles        ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_roles ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON roles        FROM anon, authenticated;
REVOKE ALL ON member_roles FROM anon, authenticated;

-- Who holds what is not a secret from the people it is exercised on.
GRANT SELECT                ON roles        TO authenticated;
GRANT INSERT, DELETE        ON roles        TO authenticated;
-- `server_id`, `is_everyone` and `legacy_key` are absent on purpose: they are
-- what a role *is*, not how it is configured, and a member with `MANAGE_ROLES`
-- moving a role to another server or claiming the baseline is not an edit.
GRANT UPDATE (name, color, position, permissions) ON roles TO authenticated;

GRANT SELECT, INSERT, DELETE ON member_roles TO authenticated;

-- `register_user` is the service role's, and it is not SECURITY DEFINER — it
-- runs as whoever called it. It now reaches `app.apply_legacy_role`, and 002
-- granted this schema to `authenticated` only, so registration failed with
-- `permission denied for schema app` the moment 018 landed. The dependency is
-- new here, so the grant belongs here.
GRANT USAGE ON SCHEMA app TO service_role;

REVOKE ALL ON FUNCTION refuse_everyone_assignment()      FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_everyone_role()           FROM PUBLIC;
REVOKE ALL ON FUNCTION sync_member_permission_cache()    FROM PUBLIC;
REVOKE ALL ON FUNCTION sync_role_permission_cache()      FROM PUBLIC;
REVOKE ALL ON FUNCTION seed_default_roles()              FROM PUBLIC;

-- ---------- roles ----------
DROP POLICY IF EXISTS roles_select ON roles;
CREATE POLICY roles_select ON roles FOR SELECT TO authenticated
  USING (server_id = app.server_id());

DROP POLICY IF EXISTS roles_insert ON roles;
CREATE POLICY roles_insert ON roles FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND NOT is_everyone
    AND app.may_manage_role(position)
    AND app.may_hold_perms(permissions)
  );

-- Both ends are checked. `USING` is the role as it stands — you may not reach a
-- role above you — and `WITH CHECK` is the role as it would be, which is what
-- stops somebody promoting a role they *can* manage to a rank they cannot.
DROP POLICY IF EXISTS roles_update ON roles;
CREATE POLICY roles_update ON roles FOR UPDATE TO authenticated
  USING (server_id = app.server_id() AND app.may_manage_role(position))
  WITH CHECK (
    server_id = app.server_id()
    AND app.may_manage_role(position)
    AND app.may_hold_perms(permissions)
  );

DROP POLICY IF EXISTS roles_delete ON roles;
CREATE POLICY roles_delete ON roles FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND app.may_manage_role(position));

-- ---------- member_roles ----------
DROP POLICY IF EXISTS member_roles_select ON member_roles;
CREATE POLICY member_roles_select ON member_roles FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM users u
                  WHERE u.id = member_roles.user_id
                    AND u.server_id = app.server_id()));

DROP POLICY IF EXISTS member_roles_insert ON member_roles;
CREATE POLICY member_roles_insert ON member_roles FOR INSERT TO authenticated
  WITH CHECK (
    app.may_assign_role(role_id)
    AND (granted_by IS NULL OR granted_by = auth.uid())
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
  );

DROP POLICY IF EXISTS member_roles_delete ON member_roles;
CREATE POLICY member_roles_delete ON member_roles FOR DELETE TO authenticated
  USING (
    app.may_assign_role(role_id)
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
  );

-- ============================================================
-- 8. What the app reads
-- ============================================================
-- One view rather than a join every client reinvents: a member's roles, in the
-- order they should be shown, with the colour that wins.

CREATE OR REPLACE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id   AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

GRANT SELECT ON member_role_list TO authenticated;
