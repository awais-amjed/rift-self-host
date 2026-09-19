#!/usr/bin/env bash
# Apply the migrations to an empty database and check the two things
# `policies_test.sql` cannot.
#
# That suite runs against a database that is *already* migrated, so it only
# ever sees the finished shape. It cannot see a file that does not apply, and
# it cannot see something reachable that nobody ever granted — because by the
# time it runs, whatever the defaults handed out is indistinguishable from
# something this schema meant.
#
# So this builds a server from nothing, in the same order an operator's console
# does, and then asks:
#
#   1. does every file apply, strictly, to an empty database;
#   2. does a brand new server come out usable — roles, an owner, a bucket;
#   3. **is anything reachable that was not granted by name.**
#
# (3) is the one worth having. Supabase's own default privileges grant EXECUTE
# on every new function in `public` to `anon` and `authenticated`, and
# `ALTER DEFAULT PRIVILEGES ... REVOKE` does not undo them — revoking from a
# default that holds no explicit grant is a no-op, which is why the blanket
# `REVOKE ALL ON ALL FUNCTIONS` in 008 has to run *after* every function
# exists. Get that order wrong and a function is world-callable with nothing
# in any file saying so. That is not hypothetical: it is how `ring_devices`
# and `has_unread_before` were once callable by anyone holding the anon key.
#
#   ./scripts/migration_test.sh
set -euo pipefail

CONTAINER="${RIFT_PG_CONTAINER:-supabase-db}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="${RIFT_SCRATCH:-rift_migration_test}"
MIGRATIONS="$ROOT/migrations"
# shellcheck source=scratch_db.sh
. "$ROOT/scripts/scratch_db.sh"

ok_line() { echo "   ok  $1"; }

# `db_test.sh` builds the database once and runs this and the policy suite
# against it. Run on its own, this builds and drops its own.
if [ -z "${RIFT_SCRATCH_READY:-}" ]; then
  rift_scratch_create
  trap rift_scratch_drop EXIT
  rift_scratch_shim
  echo "── every file applies, in order ─────────────────────────────"
  rift_scratch_migrate ok_line
fi

echo "── a server built from nothing ──────────────────────────────"
psql_scratch -v ON_ERROR_STOP=1 <<'SQL' 2>&1 | sed 's/psql:<stdin>:[0-9]*: //'
SET client_min_messages = notice;
INSERT INTO auth.users (id) VALUES
  ('aaaa1111-1111-4111-8111-000000000001'),
  ('aaaa1111-1111-4111-8111-000000000002');
INSERT INTO servers (id, name, livekit_url)
VALUES ('ffff0000-0000-4000-8000-000000000001', 'Probe', 'ws://x:7880');
INSERT INTO invites (server_id, code)
VALUES ('ffff0000-0000-4000-8000-000000000001', 'PROBECODE');
DO $$
DECLARE v_roles TEXT;
BEGIN
  PERFORM register_user('PROBECODE','aaaa1111-1111-4111-8111-000000000001','k1','s1','owner','Owner');
  PERFORM register_user('PROBECODE','aaaa1111-1111-4111-8111-000000000002','k2','s2','plain','Plain');

  -- The four roles a server is born with, and only those.
  SELECT string_agg(name, ',' ORDER BY position DESC) INTO v_roles FROM roles;
  IF v_roles IS DISTINCT FROM 'Owner,Admin,Moderator,@everyone' THEN
    RAISE EXCEPTION 'FAIL: a new server came out with roles %', v_roles;
  END IF;

  -- The first person in owns it, and holds the cached bits that follow.
  IF NOT (SELECT is_owner AND is_server_admin AND is_channel_manager
            FROM users WHERE username = 'owner') THEN
    RAISE EXCEPTION 'FAIL: the first member did not come out owning the server';
  END IF;
  IF (SELECT is_owner FROM users WHERE username = 'plain') THEN
    RAISE EXCEPTION 'FAIL: a second owner was minted';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles mr JOIN users u ON u.id = mr.user_id
              WHERE u.username = 'plain') THEN
    RAISE EXCEPTION 'FAIL: an ordinary member was given a role';
  END IF;

  -- Its own attachment bucket, minted by the trigger rather than by a backfill.
  IF NOT EXISTS (SELECT 1 FROM storage.buckets
                  WHERE id = 'chat-ffff0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: the server got no attachment bucket';
  END IF;

  -- And the scheduled work is scheduled.
  IF (SELECT count(*) FROM cron.job) < 4 THEN
    RAISE EXCEPTION 'FAIL: only % jobs were scheduled', (SELECT count(*) FROM cron.job);
  END IF;

  RAISE NOTICE 'ok  a new server comes out usable';
END $$;
SQL

echo
echo "── nothing is reachable that was not granted by name ────────"
psql_scratch -v ON_ERROR_STOP=1 <<'SQL' 2>&1 | sed 's/psql:<stdin>:[0-9]*: //'
SET client_min_messages = notice;
DO $$
DECLARE v_leaked TEXT;
BEGIN
  -- A trigger function cannot be called directly, so it is not reachable even
  -- when it is executable. Everything else that anon can call is a hole.
  SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO v_leaked
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.prorettype <> 'trigger'::regtype
     AND has_function_privilege('anon', p.oid, 'EXECUTE')
     AND NOT EXISTS (SELECT 1 FROM pg_depend d
                      WHERE d.objid = p.oid AND d.deptype = 'e');
  IF v_leaked IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: anon can call %', v_leaked;
  END IF;
  RAISE NOTICE 'ok  anon can call nothing in public';

  SELECT string_agg(c.relname || ' ' || pr.p, ', ' ORDER BY c.relname)
    INTO v_leaked
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) pr(p)
   WHERE c.relkind IN ('r','v') AND n.nspname IN ('public','app')
     AND has_table_privilege('anon', c.oid, pr.p);
  IF v_leaked IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: anon can reach %', v_leaked;
  END IF;
  RAISE NOTICE 'ok  anon can read and write no table';

  -- `authenticated` does hold USAGE on `app` — it has to, because a policy is
  -- evaluated as the querying user and every policy calls a helper there. What
  -- it must not have is the tables: the running byte total the disk cap is
  -- checked against is the schema's own bookkeeping, not an answer to give out.
  SELECT string_agg(c.relname || ' ' || pr.p, ', ' ORDER BY c.relname)
    INTO v_leaked
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) pr(p)
   WHERE c.relkind = 'r' AND n.nspname = 'app'
     AND has_table_privilege('authenticated', c.oid, pr.p);
  IF v_leaked IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: authenticated can reach app.%', v_leaked;
  END IF;
  RAISE NOTICE 'ok  the app schema''s own tables are out of a member''s reach';
END $$;
SQL
echo
echo "   migrations: passed"
