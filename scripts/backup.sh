#!/usr/bin/env bash
# Backs up what Oh-My-SSO cannot rebuild (docs/BACKUP.md): the PostgreSQL
# database, to ./backups (BACKUP_DIR). The last ten are kept. Valkey, the key
# manager and .env are not saved by default: see docs/BACKUP.md.
#
#   scripts/backup.sh [--label NAME] [--with-env] [--if-running]
#
# --with-env    also copy .env next to the dump (it holds the key manager access)
# --if-running  postgres stopped is not an error (deploy.sh, first deployment)
set -euo pipefail

KEEP_BACKUPS=10

main() {
  local label="" with_env=0 if_running=0
  while [[ $# -gt 0 ]]; do
    case $1 in
      --label) label=${2:-}; shift 2 || shift ;;
      --with-env) with_env=1; shift ;;
      --if-running) if_running=1; shift ;;
      -h | --help) sed -n '2,9p' "$0"; exit 0 ;;
      *) echo "Unknown option '$1'" >&2; exit 2 ;;
    esac
  done
  if [[ -n $label && ! $label =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid label '$label'" >&2
    exit 1
  fi

  cd "$(dirname "$0")/.."
  local dir=${BACKUP_DIR:-backups} file
  if ! docker compose ps --status running --services | grep -qx postgres; then
    echo "The postgres service is not running: no backup taken" >&2
    [[ $if_running == 1 ]] && return 0
    exit 1
  fi
  mkdir -p "$dir"
  file="$dir/sso-$(date +%Y%m%d-%H%M%S)${label:+-$label}.sql.gz"
  # pipefail: a failed pg_dump fails the pipe, and the partial file is removed.
  if ! (umask 077 && docker compose exec -T postgres pg_dump -U sso sso | gzip >"$file"); then
    rm -f "$file"
    echo "The backup failed." >&2
    exit 1
  fi
  if [[ $with_env == 1 ]]; then
    (umask 077 && cp .env "${file%.sql.gz}.env")
  fi
  echo "Database backed up to $file"

  local old
  while read -r old; do
    rm -f -- "$old" "${old%.sql.gz}.env"
  done < <(ls -1t "$dir"/sso-*.sql.gz | tail -n +$((KEEP_BACKUPS + 1)))
}

main "$@"
