#!/usr/bin/env bash
#
# Refresh the vendored copies of the schema and the server endpoints.
#
# `migrations/` and `functions/` are copies of directories that live in the app
# repo, committed here so this repo builds on its own and so a released image
# is a fixed point rather than "whatever the app repo said that day". This
# script is the only thing that should ever write to them — edit the originals.
#
#   scripts/sync.sh [path-to-rift-repo]      (default: ../rift)
#
# Deletions are propagated. That matters more than it sounds: removing a
# function from the app repo has never removed it from a running stack, so
# every server still carries endpoints that were deleted months ago.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="${1:-$here/../rift}"

if [[ ! -d "$app/self_hosted_server_migrations" ]]; then
  echo "Not a Rift app repo: $app" >&2
  echo "Usage: scripts/sync.sh [path-to-rift-repo]" >&2
  exit 1
fi

# --delete is the point of using rsync here; cp would leave removed files behind.
rsync -a --delete \
  --include='*.sql' --exclude='*' \
  "$app/self_hosted_server_migrations/" "$here/migrations/"

rsync -a --delete \
  --exclude='.dart_tool' --exclude='node_modules' --exclude='.DS_Store' \
  "$app/edge_functions/supabase/functions/" "$here/functions/"

migrations=$(find "$here/migrations" -name '*.sql' | wc -l)
functions=$(find "$here/functions" -mindepth 1 -maxdepth 1 -type d -not -name '_shared' | wc -l)

echo "Synced from $app"
echo "  $migrations migrations"
echo "  $functions functions"
echo
echo "Review with: git -C '$here' status --short"
