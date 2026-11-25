-- ============================================================
-- Rift self-hosted server — 049: editing a role touches only the members
-- it changes, and rings the member list once
-- ============================================================
-- Found in the query review of Nov 25 2026, measured the same day on a test
-- database of 50,000 members.
--
-- Each member's row carries four flags worked out from their roles
-- (`is_server_admin`, `is_channel_manager`, `can_create_tokens`, `is_owner`),
-- so a policy can read a column instead of adding up roles on every row.
-- Keeping them current cost far more than it saved:
--
--   * Any edit to a role, its name or colour included, worked the flags out
--     again for every holder, one at a time, and wrote every holder's row
--     whether anything had changed or not. Recolouring the Member role on a
--     server where 40,000 people hold it took 5.1 s, and `@everyone`, held by
--     all 50,000, 6.4 s: close to the API's 8-second limit, and past it on a
--     slower disk.
--   * Each of those writes rang `users_announce`, which sends `members` to the
--     whole server and `me` to the member: 100,000 messages for one colour,
--     and every app on the server re-reading the member list 50,000 times.
--     (The test database runs no Realtime, so the 6.4 s did not even include
--     them.)
--   * Deleting a role, or handing roles out several at a time, went through
--     the same one-at-a-time path for each holder.
--
-- Now a role's name, colour or position rings `members` once and writes
-- nobody's row. A change to its permissions works the flags out for every
-- holder in one statement, writes only the rows whose flags moved, and tells
-- each holder `me` once (their own permissions are read with the server's
-- details, which `me` re-reads), then `members` once. Changes to
-- `member_roles` are handled a statement at a time the same way.
-- `users_announce` stays quiet for the rows this writes
-- (`rift.cache_sync`), since the ringing is done here, once.
--
-- A permission edit to `@everyone` still sends one `me` per member: each
-- member's app has to re-read what it may do, and only its own topic tells
-- it. That is one message per member, not two, and not to the whole server.

-- ── Working the flags out for many members at once ──────────
-- The same sums as `app.sync_permission_cache` (one member, kept for the
-- tests that call it): `@everyone` plus every assigned role on the member's
-- server, nothing for a banned member, and `is_owner` from holding the owner
-- role.
CREATE OR REPLACE FUNCTION app.sync_permission_caches(p_users UUID[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_admin   BIGINT := app.perm('ADMINISTRATOR');
  v_channel BIGINT := app.perm('ADMINISTRATOR') | app.perm('MANAGE_CHANNELS');
  v_invite  BIGINT := app.perm('ADMINISTRATOR') | app.perm('CREATE_INVITE');
BEGIN
  IF p_users IS NULL OR cardinality(p_users) = 0 THEN
    RETURN;
  END IF;

  PERFORM set_config('rift.cache_sync', 'on', true);
  UPDATE users u
     SET is_server_admin    = f.is_admin,
         is_channel_manager = f.is_manager,
         can_create_tokens  = f.can_invite,
         is_owner           = f.owns
    FROM (
      SELECT x.id,
             (b.bits & v_admin)   <> 0 AS is_admin,
             (b.bits & v_channel) <> 0 AS is_manager,
             (b.bits & v_invite)  <> 0 AS can_invite,
             COALESCE(held.owns, false) AS owns
        FROM users x
        LEFT JOIN roles e ON e.server_id = x.server_id AND e.is_everyone
        LEFT JOIN (
          SELECT mr.user_id,
                 bit_or(r.permissions) FILTER (WHERE r.server_id = m.server_id)
                   AS bits,
                 bool_or(r.is_owner) AS owns
            FROM member_roles mr
            JOIN roles r ON r.id = mr.role_id
            JOIN users m ON m.id = mr.user_id
           WHERE mr.user_id = ANY (p_users)
           GROUP BY mr.user_id
        ) held ON held.user_id = x.id
        CROSS JOIN LATERAL (
          SELECT CASE WHEN x.is_banned THEN 0::BIGINT
                      ELSE COALESCE(e.permissions, 0) | COALESCE(held.bits, 0)
                 END AS bits
        ) b
       WHERE x.id = ANY (p_users)
    ) f
   WHERE u.id = f.id
     AND (u.is_server_admin, u.is_channel_manager, u.can_create_tokens, u.is_owner)
         IS DISTINCT FROM (f.is_admin, f.is_manager, f.can_invite, f.owns);
  PERFORM set_config('rift.cache_sync', 'off', true);
END $$;

COMMENT ON FUNCTION app.sync_permission_caches(UUID[]) IS
  'Work out the permission flags on users for many members in one statement, '
  'writing only the rows whose flags moved. users_announce stays quiet for '
  'them (rift.cache_sync): the caller rings.';

-- ── Ringing once ────────────────────────────────────────────
-- `members` once for each server involved, and `me` once to each member.
CREATE OR REPLACE FUNCTION app.announce_permission_change(p_users UUID[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() OR p_users IS NULL OR cardinality(p_users) = 0 THEN
    RETURN;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || s.server_id, true)
     FROM (SELECT DISTINCT u.server_id FROM users u WHERE u.id = ANY (p_users)) s;
  PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || u.id, true)
     FROM users u WHERE u.id = ANY (p_users);
END $$;

-- ── A role edited ───────────────────────────────────────────
CREATE OR REPLACE FUNCTION sync_role_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_role    roles%ROWTYPE;
  v_holders UUID[];
BEGIN
  -- Branch rather than COALESCE: on DELETE there is no NEW.
  IF TG_OP = 'DELETE' THEN v_role := OLD; ELSE v_role := NEW; END IF;

  -- Who holds a deleted role is answered by its `member_roles` rows, which
  -- the delete cascades to and `member_roles_sync_cache_*` handles. What
  -- is left is a change to the bits, or a new `@everyone` (a new server,
  -- whose members, if any, hold nothing else yet).
  IF TG_OP = 'UPDATE' AND OLD.permissions IS DISTINCT FROM NEW.permissions
     OR TG_OP = 'INSERT' AND NEW.is_everyone THEN
    IF v_role.is_everyone THEN
      SELECT array_agg(u.id) INTO v_holders
        FROM users u WHERE u.server_id = v_role.server_id;
    ELSE
      SELECT array_agg(mr.user_id) INTO v_holders
        FROM member_roles mr WHERE mr.role_id = v_role.id;
    END IF;
    PERFORM app.sync_permission_caches(v_holders);
    PERFORM app.announce_permission_change(v_holders);
    IF v_holders IS NOT NULL THEN
      RETURN NULL;
    END IF;
  END IF;

  -- A name, colour or position: the member list draws them, so it is told,
  -- once, and nobody's own permissions moved.
  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || v_role.server_id, true);
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS roles_sync_cache ON roles;
CREATE TRIGGER roles_sync_cache AFTER INSERT OR UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION sync_role_permission_cache();

-- ── Roles handed out or taken away ──────────────────────────
-- A statement at a time: a role deleted from 40,000 holders is one statement
-- (the cascade), not 40,000. Each member it touched hears `me` even when no
-- flag moved, as before, since a role without any of those bits still
-- changes what they may do in a channel and how they are drawn.
CREATE OR REPLACE FUNCTION sync_member_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_users UUID[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT array_agg(DISTINCT a.user_id) INTO v_users FROM added a;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT array_agg(DISTINCT r.user_id) INTO v_users FROM removed r;
  ELSE
    SELECT array_agg(DISTINCT t.user_id) INTO v_users
      FROM (SELECT a.user_id FROM added a
            UNION SELECT r.user_id FROM removed r) t;
  END IF;
  PERFORM app.sync_permission_caches(v_users);
  PERFORM app.announce_permission_change(v_users);
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS member_roles_sync_cache ON member_roles;
DROP TRIGGER IF EXISTS member_roles_sync_cache_insert ON member_roles;
CREATE TRIGGER member_roles_sync_cache_insert AFTER INSERT ON member_roles
  REFERENCING NEW TABLE AS added
  FOR EACH STATEMENT EXECUTE FUNCTION sync_member_permission_cache();
DROP TRIGGER IF EXISTS member_roles_sync_cache_update ON member_roles;
CREATE TRIGGER member_roles_sync_cache_update AFTER UPDATE ON member_roles
  REFERENCING OLD TABLE AS removed NEW TABLE AS added
  FOR EACH STATEMENT EXECUTE FUNCTION sync_member_permission_cache();
DROP TRIGGER IF EXISTS member_roles_sync_cache_delete ON member_roles;
CREATE TRIGGER member_roles_sync_cache_delete AFTER DELETE ON member_roles
  REFERENCING OLD TABLE AS removed
  FOR EACH STATEMENT EXECUTE FUNCTION sync_member_permission_cache();

-- ── users_announce stays quiet for those rows ───────────────
-- The 005 body, with the guard. Only an UPDATE is ever written under
-- `rift.cache_sync`, and only the four flags, so nothing below it (a ban, a
-- bot's manifest) can be what changed.
CREATE OR REPLACE FUNCTION app.announce_member() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row users%ROWTYPE;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'UPDATE' AND current_setting('rift.cache_sync', true) = 'on' THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || v_row.server_id, true);
  IF TG_OP <> 'INSERT' THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || v_row.id, true);
  END IF;

  -- A ban is the sweep's first rotation signal — somebody sealed into the
  -- current version who is no longer entitled to it. Both directions: the
  -- unban heals a member back into the current version.
  IF TG_OP = 'UPDATE' AND OLD.is_banned IS DISTINCT FROM NEW.is_banned THEN
    PERFORM realtime.send('{}'::jsonb, 'sweep', 'server:' || v_row.server_id, true);
  END IF;

  -- A bot arriving, leaving or publishing a new command list.
  IF v_row.is_bot AND (TG_OP <> 'UPDATE'
                       OR OLD.manifest IS DISTINCT FROM NEW.manifest) THEN
    PERFORM realtime.send('{}'::jsonb, 'bots', 'server:' || v_row.server_id, true);
  END IF;
  RETURN NULL;
END $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.sync_permission_caches(UUID[]) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_permission_change(UUID[]) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION sync_role_permission_cache() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION sync_member_permission_cache() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_member() FROM PUBLIC, anon, authenticated;
