#!/usr/bin/env bash
# Restores a dump of scripts/backup.sh into the postgres service, REPLACING the
# current database (docs/BACKUP.md): the current one is backed up first
# (before-restore), idp and idp-admin are stopped, the schema is dropped and
# recreated from the dump, Valkey is emptied (its cache would describe the
# database that was replaced), then everything is started again.
#
#   scripts/restore.sh backups/sso-20261114-101500.sql.gz --yes
#
# --yes is required. .env is not put back: restore it yourself if you need to.
set -Eeuo pipefail

main() {
  local file="" yes=0
  while [[ $# -gt 0 ]]; do
    case $1 in
      --yes) yes=1; shift ;;
      -h | --help) sed -n '2,11p' "$0"; exit 0 ;;
      -*) echo "Unknown option '$1'" >&2; exit 2 ;;
      *) file=$1; shift ;;
    esac
  done
  if [[ -z $file ]]; then
    echo "Usage: $0 DUMP.sql.gz --yes" >&2
    exit 1
  fi
  if [[ ! -s $file ]] || ! gzip -t "$file"; then
    echo "'$file' is not a readable gzip dump: nothing was changed" >&2
    exit 1
  fi
  if [[ $yes != 1 ]]; then
    echo "This replaces the current database with $file. Run again with --yes." >&2
    exit 1
  fi
  file=$(realpath "$file")

  cd "$(dirname "$0")/.."
  local services
  services=$(docker compose config --services)
  has() { grep -qx "$1" <<<"$services"; }

  has postgres || { echo "No postgres service in compose.yml" >&2; exit 1; }
  # pg_dump ends its output with this marker: a truncated file is refused.
  if ! zcat "$file" | tail -n 10 | grep -q 'PostgreSQL database dump complete'; then
    echo "'$file' looks truncated: nothing was changed" >&2
    exit 1
  fi
  docker compose up -d --wait postgres
  # The current data is about to be replaced: keep it, and stop here if that fails.
  scripts/backup.sh --label before-restore
  trap 'echo "The restore did not finish: idp and idp-admin may be stopped. Fix the error, then run: docker compose up -d" >&2' ERR
  has idp && docker compose stop idp
  has idp-admin && docker compose stop idp-admin

  # One transaction (-1): a dump that fails halfway leaves the database as it was.
  {
    echo 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
    zcat "$file"
  } | docker compose exec -T postgres psql -U sso sso -v ON_ERROR_STOP=1 -q -1 >/dev/null
  echo "Database restored from $file"

  if has valkey; then
    docker compose up -d --wait valkey
    docker compose exec -T valkey sh -c 'REDISCLI_AUTH=${VALKEY_PASSWORD:-} valkey-cli FLUSHALL' >/dev/null
    echo "Valkey emptied: everyone is signed out"
  fi
  # migrate runs again before idp and idp-admin: a dump older than the code is
  # brought up to date.
  docker compose up -d
}

main "$@"
