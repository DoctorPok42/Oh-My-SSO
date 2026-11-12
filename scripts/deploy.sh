#!/usr/bin/env bash
# Deploys a version of Oh-My-SSO on the production host (docs/PRODUCTION.md,
# "Update"): pulls the images of the new tag, writes the tag in .env, backs up
# the database, then recreates the containers that changed. The migrations are
# in the migrate image of the tag: they always match the code deployed.
#
#   scripts/deploy.sh --package all --version <sha of a commit of main>
#   scripts/deploy.sh --package idp --version latest
#   scripts/deploy.sh --package all --version <sha> --no-backup
#
# Runs in the repository root, wherever it is called from: .env and
# compose.yml must be there. Backups go to ./backups (BACKUP_DIR), the last
# ten are kept.
set -euo pipefail

PACKAGES=(idp idp-admin migrate admin)
KEEP_BACKUPS=10

usage() {
  cat <<EOF
Deploy a version of the Oh-My-SSO images.

Usage: $0 --package PACKAGE --version TAG [--no-backup]

  --package    ${PACKAGES[*]}, or all (every image at the same version).
               idp and idp-admin bring migrate with them: the schema and the
               code of a version go together.
  --version    image tag: the sha of a commit of main whose CI passed, or latest
  --no-backup  do not dump the database before the containers are recreated
  -h, --help   this help
EOF
}

# idp-admin -> IMAGE_IDP_ADMIN, the variable of compose.yml (compose cannot
# read a variable whose name has a "-").
image_var() {
  local name=${1^^}
  echo "IMAGE_${name//-/_}"
}

# Dumps the database to $BACKUP_DIR before a deploy: the migrations that follow
# are not automatically reversible. Only the database: the keys of the key
# manager and .env are backed up separately (docs/PRODUCTION.md).
backup_database() {
  local version=$1 dir=${BACKUP_DIR:-backups} file
  if ! docker compose ps --status running --services | grep -qx postgres; then
    echo "The postgres service is not running: no backup taken" >&2
    return 0
  fi
  mkdir -p "$dir"
  file="$dir/sso-$(date +%Y%m%d-%H%M%S)-before-$version.sql.gz"
  if ! (umask 077 && docker compose exec -T postgres pg_dump -U sso sso | gzip >"$file"); then
    rm -f "$file"
    echo "The backup failed: nothing was deployed. Fix it, or use --no-backup." >&2
    exit 1
  fi
  echo "Database backed up to $file"
  ls -1t "$dir"/sso-*.sql.gz | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm --
}

main() {
  local package="" version="" backup=1
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h | --help) usage; exit 0 ;;
      --package) package=${2:-}; shift 2 || shift ;;
      --version) version=${2:-}; shift 2 || shift ;;
      --no-backup) backup=0; shift ;;
      *) echo "Unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
  done
  if [[ -z $package || -z $version ]]; then
    usage >&2
    exit 1
  fi

  local targets=()
  if [[ $package == all ]]; then
    targets=("${PACKAGES[@]}")
  elif [[ " ${PACKAGES[*]} " == *" $package "* ]]; then
    targets=("$package")
    if [[ $package == idp || $package == idp-admin ]]; then
      targets+=(migrate)
    fi
  else
    echo "Unknown package '$package': ${PACKAGES[*]} or all" >&2
    exit 1
  fi
  if [[ ! $version =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid version '$version'" >&2
    exit 1
  fi

  cd "$(dirname "$0")/.."
  if [[ ! -f .env || ! -f compose.yml ]]; then
    echo "No .env or compose.yml in $PWD: see docs/PRODUCTION.md" >&2
    exit 1
  fi

  # Pull with the new tags given to compose only (the environment wins over
  # .env): .env changes once the images exist. A tag the CI has not pushed
  # yet stops here, and nothing changes.
  local vars=() p
  for p in "${targets[@]}"; do
    vars+=("$(image_var "$p")=$version")
  done
  env "${vars[@]}" docker compose pull

  # Before .env changes: if the backup fails, nothing is deployed, and a later
  # `docker compose up` does not deploy the new tags either. Only a deploy
  # that brings migrations needs one.
  if [[ $backup == 1 && " ${targets[*]} " == *" migrate "* ]]; then
    backup_database "$version"
  fi

  local kv var
  for kv in "${vars[@]}"; do
    var=${kv%%=*}
    if grep -q "^${var}=" .env; then
      sed -i "s#^${var}=.*#${kv}#" .env
    else
      echo "$kv" >>.env
    fi
    echo "$kv"
  done

  # Recreates the containers whose image or settings changed; the migrate
  # service runs again before idp and idp-admin start.
  docker compose up -d --remove-orphans
}

main "$@"
