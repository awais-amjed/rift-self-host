#!/usr/bin/env bash
# Run the migration-path test and the policy tests for this schema.
#
# Both run against a Postgres container — by default the one the app's local
# development stack runs, since a Rift server's database is an ordinary
# Supabase Postgres. The suite ends in ROLLBACK, so it writes nothing; a
# failure raises, which aborts the transaction and exits non-zero.
#
# The central tier has its own, in the `rift-central` repository.
#
#   ./scripts/db_test.sh
set -euo pipefail

CONTAINER="${RIFT_PG_CONTAINER:-supabase-db}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

psql_main() { docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 "$@"; }

echo "── migration path ──────────────────────────────────────────"
"$ROOT/scripts/migration_test.sh"

echo
echo "── self-hosted ─────────────────────────────────────────────"
psql_main -f - < "$ROOT/migrations/tests/policies_test.sql" 2>&1 |
  sed 's/psql:<stdin>:[0-9]*: //'
echo "   self-hosted: passed"
