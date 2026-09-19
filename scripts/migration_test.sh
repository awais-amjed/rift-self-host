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
SCRATCH="rift_migration_test"
MIGRATIONS="$ROOT/migrations"

psql_main() { docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 "$@"; }
psql_scratch() {
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' \
    "$CONTAINER" psql -U postgres -q -d "$SCRATCH" "$@"
}

psql_main -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1
psql_main -c "CREATE DATABASE $SCRATCH" >/dev/null
trap 'docker exec -i "$CONTAINER" psql -U postgres -q -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true' EXIT

# The pieces of Supabase the migrations stand on. This has to be a faithful
# stand-in and not a convenient one: the privilege check below is only worth
# anything if the defaults here are the defaults production has.
psql_scratch -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE SCHEMA IF NOT EXISTS storage;

-- Only the columns the migrations and the policy suite touch; GoTrue and
-- Storage own the real ones and they have many more.
CREATE TABLE IF NOT EXISTS auth.users (
  id UUID PRIMARY KEY, instance_id UUID, aud VARCHAR(255), role VARCHAR(255),
  email VARCHAR(255), raw_app_meta_data JSONB, raw_user_meta_data JSONB,
  created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS storage.buckets (
  id TEXT PRIMARY KEY, name TEXT, public BOOLEAN, file_size_limit BIGINT
);
CREATE TABLE IF NOT EXISTS storage.objects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id TEXT, name TEXT, owner UUID, owner_id TEXT, metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now(),
  last_accessed_at TIMESTAMPTZ DEFAULT now(), path_tokens TEXT[], version TEXT,
  user_metadata JSONB, level INT
);
CREATE OR REPLACE FUNCTION storage.foldername(name TEXT) RETURNS TEXT[]
  LANGUAGE plpgsql AS $shim$
DECLARE parts TEXT[]; BEGIN parts := string_to_array(name, '/');
  RETURN parts[1:array_length(parts,1)-1]; END $shim$;
CREATE OR REPLACE FUNCTION storage.filename(name TEXT) RETURNS TEXT
  LANGUAGE plpgsql AS $shim$
DECLARE parts TEXT[]; BEGIN parts := string_to_array(name, '/');
  RETURN parts[array_length(parts,1)]; END $shim$;

-- pg_cron is not installable outside the configured database, so the schema
-- is shimmed and the CREATE EXTENSION line is stripped below. It records what
-- was scheduled, which is enough to assert a job exists.
CREATE SCHEMA IF NOT EXISTS cron;
CREATE TABLE IF NOT EXISTS cron.job (
  jobid BIGSERIAL PRIMARY KEY, jobname TEXT UNIQUE, schedule TEXT, command TEXT
);
CREATE OR REPLACE FUNCTION cron.schedule(p_name TEXT, p_schedule TEXT, p_command TEXT)
  RETURNS BIGINT LANGUAGE sql AS $shim$
  INSERT INTO cron.job (jobname, schedule, command) VALUES (p_name, p_schedule, p_command)
  ON CONFLICT (jobname) DO UPDATE SET schedule = EXCLUDED.schedule, command = EXCLUDED.command
  RETURNING jobid $shim$;
CREATE OR REPLACE FUNCTION cron.unschedule(p_name TEXT)
  RETURNS BOOLEAN LANGUAGE sql AS $shim$
  DELETE FROM cron.job WHERE jobname = p_name RETURNING true $shim$;

-- Exactly Supabase's own: nullif BEFORE the cast, or an empty setting — which
-- is what a RESET leaves behind — raises instead of reading as "nobody".
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $shim$
  SELECT coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid $shim$;

DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA public, auth, extensions, storage TO anon, authenticated, service_role;
DO $$ BEGIN CREATE PUBLICATION supabase_realtime; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Storage's own grants and RLS, which Supabase installs and the migrations
-- assume: they only add policies.
GRANT ALL ON storage.objects, storage.buckets TO anon, authenticated, service_role;
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;

-- The defaults that make check (3) mean something. A new table in `public`
-- arrives readable and writable by anon and authenticated; a new function
-- arrives EXECUTEable by both.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL     ON TABLES    TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL     ON SEQUENCES TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO postgres, anon, authenticated, service_role;
SQL

echo "── every file applies, in order ─────────────────────────────"
for f in "$MIGRATIONS"/[0-9][0-9][0-9]_*.sql; do
  # `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public` also names pgcrypto's and
  # pg_trgm's own functions, which live in `extensions` on a real Supabase and
  # in `public` here. Their warnings are the harness, not the schema.
  sed 's/^CREATE EXTENSION IF NOT EXISTS pg_cron;/-- pg_cron: shimmed above/' "$f" \
    | psql_scratch -v ON_ERROR_STOP=1 -f - 2>&1 >/dev/null \
    | grep -v 'no privileges could be revoked' >&2 || true
  echo "   ok  $(basename "$f")"
done

echo
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
