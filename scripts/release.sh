#!/usr/bin/env bash
# Makes a release of the console image: sets VERSION, names that version as the
# console in docker-compose.yml, records the file in the list of published ones
# (scripts/known_compose.sh), commits the three and tags the commit.
#
#   scripts/release.sh 1.0.0                 # a release
#   scripts/release.sh 1.1.0-beta.1          # a pre-release: anything with a `-`
#   scripts/release.sh 1.0.0 notes.md        # release notes from a file
#
# The tag's message is the release's notes, so without a notes file git opens
# an editor for them. VERSION is what the console records in a database when it
# brings a stack up to date, so every image that changes anything needs a new
# one.
#
# The website hands out docker-compose.yml to new servers: once this release's
# image is published, copy it there (scripts/sync-self-host.sh in
# rift-website).
#
# Nothing is pushed. When the commit and the tag look right:
#
#   git push origin HEAD v1.0.0
#
# The push mirror carries the tag to GitHub, where
# .github/workflows/release.yml builds the image and publishes it.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: scripts/release.sh <version> [notes-file], e.g. 1.0.0 or 1.1.0-beta.1}
notes=${2:-}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
  { echo "Not a version: $version (expected 1.0.0 or 1.1.0-beta.1)" >&2; exit 1; }
[[ -z $notes || -f $notes ]] || { echo "No such notes file: $notes" >&2; exit 1; }
git diff --quiet && git diff --cached --quiet ||
  { echo "Commit or stash your changes first." >&2; exit 1; }
! git rev-parse -q --verify "refs/tags/v$version" >/dev/null ||
  { echo "v$version already exists." >&2; exit 1; }

current=$(tr -d '[:space:]' < VERSION)
[[ $current != "$version" ]] || { echo "VERSION is already $current." >&2; exit 1; }

echo "$version" > VERSION
# The image carries this file, and the console checks that the two agree.
sed -i -E "s|(ghcr\.io/awais-amjed/rift-console:)[^}[:space:]]+|\1$version|" docker-compose.yml
grep -q "rift-console:$version}" docker-compose.yml ||
  { git checkout -q -- VERSION docker-compose.yml; echo "Could not name the console in docker-compose.yml." >&2; exit 1; }
scripts/known_compose.sh >/dev/null
git commit -q -m "Release $version" -- VERSION docker-compose.yml console/known-compose.sha256
# An empty message (the editor closed without notes) refuses the tag; take the
# commit back with it, so a second try starts from where this one did.
if ! git tag -a "v$version" ${notes:+-F "$notes"}; then
  git reset -q --hard HEAD~1
  echo "No tag made; VERSION is back to $current." >&2
  exit 1
fi
echo "Tagged v$version. Push with: git push origin HEAD v$version"
