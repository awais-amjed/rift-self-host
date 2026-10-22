#!/usr/bin/env bash
# Makes a release of the console image: sets VERSION, names that version as the
# console in docker-compose.yml, records the file in the list of published ones
# (scripts/known_compose.sh), commits them and tags the commit.
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
# The release workflow attaches docker-compose.yml to the GitHub release, and
# the website's install link redirects to the newest full release's copy, so a
# new server gets this one as soon as its image is published.
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
# Added rather than named to commit: this release's copy in known-compose/ is a
# new file, and a path given to commit takes only files git already tracks.
git add -- VERSION docker-compose.yml console/known-compose.sha256 console/known-compose
git commit -q -m "Release $version"
# An empty message (the editor closed without notes) refuses the tag; take the
# commit back with it, so a second try starts from where this one did.
if ! git tag -a "v$version" ${notes:+-F "$notes"}; then
  git reset -q --hard HEAD~1
  echo "No tag made; VERSION is back to $current." >&2
  exit 1
fi
echo "Tagged v$version. Push with: git push origin HEAD v$version"
