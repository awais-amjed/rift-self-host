#!/usr/bin/env bash
# Build a scratch database that stands in for a Supabase project, and apply
# every migration to it. Sourced by `migration_test.sh` and `db_test.sh`, so
# both test the schema this repository ships rather than whatever happens to
# be in a long-lived development database.
#
# The stand-in has to be faithful and not convenient. Two shims were wrong for
# a long time and both hid real behaviour: `auth.uid()` casting before its
# `nullif` (Supabase's does the opposite, and the empty string a `RESET` leaves
# behind then raises instead of reading as "nobody"), and no default privileges
# at all — which made the "what can anon reach" check vacuous, because the
# thing it looks for is what Supabase's defaults hand out.
#
# Expects CONTAINER, SCRATCH and MIGRATIONS to be set. Defines psql_scratch.

psql_scratch() {
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' \
    "$CONTAINER" psql -U postgres -q -d "$SCRATCH" "$@"
}

rift_scratch_create() {
  docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1
  docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE $SCRATCH" >/dev/null
}

rift_scratch_drop() {
  docker exec -i "$CONTAINER" psql -U postgres -q \
    -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true
}

rift_scratch_shim() {
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
-- Storage's own index, and the collation is the point: `(bucket_id, name
-- COLLATE "C")` is what makes a prefix range on a folder an index scan, and
-- the avatar ceiling in 006 is written against it. Without it here the suite
-- would pass on a sequential scan and say nothing about the shape production
-- actually runs.
CREATE INDEX IF NOT EXISTS idx_objects_bucket_id_name
  ON storage.objects (bucket_id, name COLLATE "C");

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
}

# Apply every migration, strictly, in filename order. $1 is an optional
# callback invoked with each filename as it succeeds.
rift_scratch_migrate() {
  local report="${1:-}"
  local f
  for f in "$MIGRATIONS"/[0-9][0-9][0-9]_*.sql; do
    # `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public` also names pgcrypto's and
    # pg_trgm's own functions, which live in `extensions` on a real Supabase
    # and in `public` here. Their warnings are the harness, not the schema.
    sed 's/^CREATE EXTENSION IF NOT EXISTS pg_cron;/-- pg_cron: shimmed above/' "$f" \
      | psql_scratch -v ON_ERROR_STOP=1 -f - 2>&1 >/dev/null \
      | grep -v 'no privileges could be revoked' >&2 || true
    [ -n "$report" ] && "$report" "$(basename "$f")"
  done
  return 0
}
