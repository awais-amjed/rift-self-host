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
