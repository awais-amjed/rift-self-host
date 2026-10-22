#!/usr/bin/env bash
# Writes console/known-compose.sha256: the hash of every version of
# docker-compose.yml this repository has ever held, and of the one in the
# working tree. And console/known-compose/, each of those versions named by its
# hash.
#
# The console's Update replaces an operator's compose file only when its hash
# is on this list — when it is a file somebody downloaded and never edited —
# and otherwise merges their edits into the new one, from the version closest
# to theirs: the one they downloaded. The image carries the versions because
# the build sees one commit, not the history. Every commit's version is on it,
# not only releases', because the website hands out whichever one was synced
# last, and that is sometimes between releases.
#
# scripts/release.sh runs it, so each image knows every file published before
# it, and its own.
set -euo pipefail
cd "$(dirname "$0")/.."

out=console/known-compose.sha256
versions=console/known-compose
rm -rf "$versions"
mkdir -p "$versions"
keep() {
  local text hash
  text=$(cat; echo .)
  hash=$(printf '%s' "${text%.}" | sha256sum | cut -c1-64)
  printf '%s' "${text%.}" > "$versions/$hash.yml"
  echo "$hash"
}
{
  echo "# Every published docker-compose.yml, by sha256. Written by scripts/known_compose.sh."
  {
    for commit in $(git log --format=%H -- docker-compose.yml); do
      git show "${commit}:docker-compose.yml" | keep
    done
    keep < docker-compose.yml
  } | sort -u
} > "$out"
echo "$(($(wc -l < "$out") - 1)) versions in $out and $versions/"
