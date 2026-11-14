#!/usr/bin/env bash
# Deploys a version of Oh-My-SSO on the production host (docs/PRODUCTION.md,
# "Update"): pulls the images of the new tag, writes the tag in .env, backs up
# the database, then recreates the containers that changed. The migrations are
# in the migrate image of the tag: they always match the code deployed.
#
#   scripts/deploy.sh --package all --version <sha of a commit of main>
#   scripts/deploy.sh --package idp --version 1.2.3
#   scripts/deploy.sh --package all --version <sha> --no-backup
#
# Runs in the repository root, wherever it is called from: .env and
# compose.yml must be there. Backups go to ./backups (BACKUP_DIR), the last
# ten are kept.
set -euo pipefail

PACKAGES=(idp idp-admin migrate admin)

usage() {
  cat <<EOF
Deploy a version of the Oh-My-SSO images.

Usage: $0 --package PACKAGE --version TAG [--no-backup]

  --package    ${PACKAGES[*]}, or all (every image at the same version).
               idp and idp-admin bring migrate with them: the schema and the
               code of a version go together.
  --version    image tag: a release (1.2.3) or the sha of a commit of main whose CI passed
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

# In production, idp and idp-admin refuse to start without VALKEY_PASSWORD,
# and the valkey service of compose.yml must require it (compose.example.yml).
# Checked before anything changes: otherwise the new containers would not
# start, and the old ones would be gone.
check_valkey_password() {
  grep -q '^APP_ENV=production[[:space:]]*$' .env || return 0
  if ! grep -q '^VALKEY_PASSWORD=[^[:space:]]' .env; then
    echo "VALKEY_PASSWORD is not set in .env: idp and idp-admin refuse to start without it in production." >&2
    echo "Set it (openssl rand -hex 32) and pass it to the valkey service of compose.yml: docs/PRODUCTION.md, Update." >&2
    exit 1
  fi
  if grep -q '^  valkey:' compose.yml && ! grep -q 'requirepass' compose.yml; then
    echo "The valkey service of compose.yml does not require VALKEY_PASSWORD (--requirepass): see compose.example.yml." >&2
    exit 1
  fi
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
  if [[ " ${targets[*]} " == *" idp "* || " ${targets[*]} " == *" idp-admin "* ]]; then
    check_valkey_password
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
    # The migrations that follow are not automatically reversible. Only the
    # database: the key manager and .env are backed up separately (docs/BACKUP.md).
    scripts/backup.sh --if-running --label "before-$version" ||
      { echo "Nothing was deployed. Fix the backup, or use --no-backup." >&2; exit 1; }
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
