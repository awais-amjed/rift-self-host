#!/usr/bin/env bash
# Run both of this schema's suites, against a scratch database built from the
# migrations in this repository.
#
# It used to run the policy suite against the development stack's live
# database, which meant a new migration had to be applied there by hand before
# its own tests would pass — and meant the suite was only ever as honest as
# that database. It now builds one from nothing, applies every file, and runs
# both phases against it:
#
#   1. `migration_test.sh` — every file applies, a new server comes out
#      usable, and nothing is reachable that nobody granted by name;
#   2. `policies_test.sql` — what each role may actually reach.
#
# The suite ends in ROLLBACK and the database is dropped afterwards, so this
# writes nothing anywhere.
#
# The central tier has its own, in the `rift-central` repository.
#
#   ./scripts/db_test.sh
set -euo pipefail

CONTAINER="${RIFT_PG_CONTAINER:-supabase-db}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="rift_db_test"
MIGRATIONS="$ROOT/migrations"
# shellcheck source=scratch_db.sh
. "$ROOT/scripts/scratch_db.sh"

ok_line() { echo "   ok  $1"; }

echo "── no shipped migration was edited ─────────────────────────"
"$ROOT/scripts/check_locked.sh"
echo

rift_scratch_create
trap rift_scratch_drop EXIT
rift_scratch_shim

echo "── every file applies, in order ─────────────────────────────"
rift_scratch_migrate ok_line

echo
RIFT_SCRATCH_READY=1 RIFT_SCRATCH="$SCRATCH" "$ROOT/scripts/migration_test.sh"

echo
echo "── self-hosted ─────────────────────────────────────────────"
# Not `psql_scratch`: that pins client_min_messages to warning so the
# migrations' DROP ... IF EXISTS chatter stays out of the way, and the suite
# speaks entirely in NOTICE.
docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 -d "$SCRATCH" \
  -f - < "$ROOT/migrations/tests/policies_test.sql" 2>&1 |
  sed 's/psql:<stdin>:[0-9]*: //'
echo "   self-hosted: passed"
