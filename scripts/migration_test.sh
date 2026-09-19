#!/usr/bin/env bash
# Apply the self-hosted migrations to an empty database and check that the one
# thing a migration can do that a policy cannot — lose data — did not happen.
#
# `policies_test.sql` runs against a database that is *already* migrated, so it
# can only ever see the finished shape. It cannot see a migration reading a
# column it has already overwritten, which is what 018 did: creating the
# `@everyone` role fired the trigger that recomputes `is_server_admin` from a
# member's roles — none, yet — and the backfill then read those zeroes and
# granted nobody anything. Every server came out with no administrator.
#
# So this walks the path instead. It stops where 018 would run, writes the
# permissions a real server would have had at that point, and checks they are
# still there on the other side.
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

psql_main -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null
psql_main -c "CREATE DATABASE $SCRATCH" >/dev/null
trap 'docker exec -i "$CONTAINER" psql -U postgres -q -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true' EXIT

# The pieces of Supabase the migrations lean on, same shims as db_test.sh.
psql_scratch -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS extensions;
-- 008 puts a trigger on `servers` that gives each one its own storage bucket.
-- Only the columns it writes; this is a landing pad, not Supabase Storage.
CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.buckets (
  id TEXT PRIMARY KEY,
  name TEXT,
  public BOOLEAN,
  file_size_limit BIGINT
);
-- 029 puts triggers on `storage.objects` — a running total of what each
-- bucket holds, and the check that refuses the upload which would go over.
-- Unlike 002's policies on the same table, those are past the best-effort
-- pass and so must actually apply. Only the columns they read.
CREATE TABLE IF NOT EXISTS storage.objects (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id TEXT,
  name      TEXT,
  owner     UUID,
  metadata  JSONB
);
CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);
-- pg_cron is not installed here and `CREATE EXTENSION` in 006 is swallowed with
-- the rest of the pre-roles best-effort pass. Later migrations that *schedule*
-- something are not swallowed, and one aborts the whole file — so the schema is
-- shimmed rather than each migration learning to guard itself. It records what
-- was scheduled, which is enough for `cron.unschedule ... WHERE EXISTS` to
-- behave and for a test to assert a job exists.
CREATE SCHEMA IF NOT EXISTS cron;
CREATE TABLE IF NOT EXISTS cron.job (
  jobid    BIGSERIAL PRIMARY KEY,
  jobname  TEXT UNIQUE,
  schedule TEXT,
  command  TEXT
);
CREATE OR REPLACE FUNCTION cron.schedule(p_name TEXT, p_schedule TEXT, p_command TEXT)
  RETURNS BIGINT LANGUAGE sql AS $shim$
  INSERT INTO cron.job (jobname, schedule, command) VALUES (p_name, p_schedule, p_command)
  ON CONFLICT (jobname) DO UPDATE SET schedule = EXCLUDED.schedule, command = EXCLUDED.command
  RETURNING jobid $shim$;
CREATE OR REPLACE FUNCTION cron.unschedule(p_name TEXT)
  RETURNS BOOLEAN LANGUAGE sql AS $shim$
  DELETE FROM cron.job WHERE jobname = p_name RETURNING true $shim$;
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$;
DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA public, auth, extensions, storage TO anon, authenticated, service_role;
DO $$ BEGIN CREATE PUBLICATION supabase_realtime; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SQL

# Which migration a file is, as a number. The two loops below used to select
# by glob — `0[01][0-7]_*` for "before roles" and `0[12][0-9]_*` for "after" —
# and both were quietly wrong: the first matched neither 008 nor 009, and the
# second stopped dead at 029, so 030 was never applied by this test at all and
# 031 would not have been either. A range spelled as a pattern is a range that
# expires without saying so.
number_of() { basename "$1" | cut -d_ -f1 | sed 's/^0*//'; }

# The first migration that has roles in it, and the point this test stops at.
# Was 18 under the old numbering; the compaction into 12 files made it 006,
# and the number here was not moved with it — so every file applied *before*
# the fixture, the backfill found nobody, and the test failed on a path no
# server has ever taken.
ROLES_MIGRATION=6

# Everything before roles existed. Best-effort: the scheduling and storage
# migrations need extensions only the real stack has, and nothing this test
# asserts depends on them — but `users`, `servers` and `invites` do have to be
# there, and the check below fails loudly if they are not.
for f in "$MIGRATIONS"/[0-9][0-9][0-9]_*.sql; do
  [ "$(number_of "$f")" -lt "$ROLES_MIGRATION" ] || continue
  psql_scratch -f - < "$f" >/dev/null 2>&1 || true
done

psql_scratch -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DO $$
BEGIN
  IF to_regclass('public.users') IS NULL OR to_regclass('public.invites') IS NULL THEN
    RAISE EXCEPTION 'pre-018 schema did not apply; this test proves nothing';
  END IF;
END $$;
SQL

# A server as it stood the day before 018: three members, three different
# standings, all of it in the three columns.
psql_scratch -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO auth.users (id) VALUES
  ('aaaa1111-1111-4111-8111-000000000001'),
  ('aaaa1111-1111-4111-8111-000000000002'),
  ('aaaa1111-1111-4111-8111-000000000003');
INSERT INTO servers (id, name, livekit_url)
VALUES ('ffff0000-0000-4000-8000-000000000001', 'Legacy', 'ws://x:7880');
INSERT INTO users (id, server_id, username, display_name, public_key, stable_id,
                   is_server_admin, is_channel_manager, can_create_tokens)
VALUES
  ('aaaa1111-1111-4111-8111-000000000001','ffff0000-0000-4000-8000-000000000001',
   'owner','Owner','k1','s1', true,  true,  true),
  ('aaaa1111-1111-4111-8111-000000000002','ffff0000-0000-4000-8000-000000000001',
   'mod','Mod','k2','s2',     false, true,  true),
  ('aaaa1111-1111-4111-8111-000000000003','ffff0000-0000-4000-8000-000000000001',
   'plain','Plain','k3','s3', false, false, true);
SQL

echo "── migrations 018 onward ────────────────────────────────────"
# Strict from here: this is the half the test is about, and a migration that
# cannot apply to a real path is the failure being looked for.
for f in "$MIGRATIONS"/[0-9][0-9][0-9]_*.sql; do
  [ "$(number_of "$f")" -ge "$ROLES_MIGRATION" ] || continue
  psql_scratch -v ON_ERROR_STOP=1 -f - < "$f" >/dev/null
done

psql_scratch -v ON_ERROR_STOP=1 <<'SQL' 2>&1 | sed 's/psql:<stdin>:[0-9]*: //'
DO $$
DECLARE v_roles TEXT;
BEGIN
  -- The three columns are a cache of three bits now. If the backfill read them
  -- after its own trigger had zeroed them, every one of these is false and the
  -- server has no administrator — which is a server nobody can ever administer,
  -- because handing out a role needs a role.
  IF NOT (SELECT is_server_admin FROM users WHERE username = 'owner') THEN
    RAISE EXCEPTION 'FAIL: the server admin was not carried across';
  END IF;
  IF NOT (SELECT is_channel_manager FROM users WHERE username = 'mod') THEN
    RAISE EXCEPTION 'FAIL: the channel manager was not carried across';
  END IF;
  IF (SELECT is_server_admin FROM users WHERE username = 'mod') THEN
    RAISE EXCEPTION 'FAIL: a channel manager came out an administrator';
  END IF;
  IF NOT (SELECT can_create_tokens FROM users WHERE username = 'plain') THEN
    RAISE EXCEPTION 'FAIL: an ordinary member lost their invites';
  END IF;

  -- And the roles behind them, since the columns are only the shadow.
  SELECT string_agg(r.name, ',' ORDER BY r.position DESC) INTO v_roles
    FROM member_roles mr JOIN roles r ON r.id = mr.role_id
    JOIN users u ON u.id = mr.user_id
   WHERE u.username = 'owner';
  -- 013 adds the top rung: the longest-standing admin owns the server.
  -- 016 takes the bottom one away: Members is gone, its one bit on @everyone.
  IF v_roles IS DISTINCT FROM 'Owner,Admin,Moderator' THEN
    RAISE EXCEPTION 'FAIL: the owner came out holding %', v_roles;
  END IF;
  IF NOT (SELECT is_owner FROM users WHERE username = 'owner') THEN
    RAISE EXCEPTION 'FAIL: the owner is not cached as the owner';
  END IF;
  IF (SELECT is_owner FROM users WHERE username = 'mod') THEN
    RAISE EXCEPTION 'FAIL: a second person came out owning the server';
  END IF;
  RAISE NOTICE 'ok  a server''s standings survive the move to roles';
END $$;
SQL
echo "   migrations: passed"
