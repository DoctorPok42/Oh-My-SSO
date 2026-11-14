#!/usr/bin/env bash
# Tests of scripts/release_notes.sh on a throwaway CHANGELOG.md.
#   scripts/release_notes_test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/scripts"
cp "$here/release_notes.sh" "$work/scripts/"
cat >"$work/CHANGELOG.md" <<'MD'
# Changelog

## [Unreleased]
- next

## [1.2.0] - 2026-11-14
Manual step: set X.
- second

## [1.1.0] - 2026-10-01

## [1.0.0-rc.1] - 2026-09-01
- candidate
MD

failures=0
check() {
  if [[ $2 == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; failures=$((failures + 1)); fi
}
notes() { "$work/scripts/release_notes.sh" "$1" 2>/dev/null && echo "status=0" || echo "status=$?"; }

check "notes stop at the next section" "$(notes v1.2.0 | tr '\n' '|')" "Manual step: set X.|- second|status=0|"
check "pre-release" "$(notes v1.0.0-rc.1 | head -1)" "- candidate"
check "empty section is refused" "$(notes v1.1.0 | tail -1)" "status=1"
check "unknown version is refused" "$(notes v9.9.9 | tail -1)" "status=1"
check "Unreleased is not a version" "$(notes vUnreleased | tail -1)" "status=1"
check "tag without v is refused" "$(notes 1.2.0 | tail -1)" "status=1"
check "1.2 is not semver" "$(notes v1.2 | tail -1)" "status=1"

if ((failures > 0)); then echo "$failures failure(s)"; exit 1; fi
