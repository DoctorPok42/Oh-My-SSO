#!/usr/bin/env bash
# Prints the CHANGELOG.md notes of a release, and fails if the tag is not a
# semantic version or its section is missing or empty: the release workflow
# runs it first, so nothing is published without notes.
#   scripts/release_notes.sh v1.2.3
set -euo pipefail

tag=${1:?Usage: $0 vX.Y.Z}
version=${tag#v}
if [[ $tag != v* || ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "'$tag' is not a semantic version tag (vX.Y.Z)" >&2
  exit 1
fi
cd "$(dirname "$0")/.."
notes=$(awk -v h="## [$version]" 'index($0, h) == 1 { f = 1; next } /^## / { f = 0 } f' CHANGELOG.md)
if [[ -z ${notes//[[:space:]]/} ]]; then
  echo "CHANGELOG.md has no notes under '## [$version]'" >&2
  exit 1
fi
printf '%s\n' "$notes"
