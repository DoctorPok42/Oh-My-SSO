#!/usr/bin/env bash
# Deploys a version of Oh-My-SSO on the production host (docs/PRODUCTION.md,
# "Update"): updates this checkout (the migrations), pulls the images of the
# new tag, writes the tag in .env, then recreates the containers that changed.
#
#   scripts/deploy.sh --package all --version <sha of a commit of main>
#   scripts/deploy.sh --package idp --version latest
#
# Runs in the repository root, wherever it is called from: .env and
# compose.yml must be there.
set -euo pipefail

PACKAGES=(idp idp-admin admin)

usage() {
  cat <<EOF
Deploy a version of the Oh-My-SSO images.

Usage: $0 --package PACKAGE --version TAG

  --package   ${PACKAGES[*]}, or all (the three at the same version)
  --version   image tag: the sha of a commit of main whose CI passed, or latest
  -h, --help  this help
EOF
}

# idp-admin -> IMAGE_IDP_ADMIN, the variable of compose.yml (compose cannot
# read a variable whose name has a "-").
image_var() {
  local name=${1^^}
  echo "IMAGE_${name//-/_}"
}

main() {
  local package="" version=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h | --help) usage; exit 0 ;;
      --package) package=${2:-}; shift 2 || shift ;;
      --version) version=${2:-}; shift 2 || shift ;;
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

  # The migrations the migrate service applies come from this checkout.
  git pull --ff-only

  # Pull with the new tags given to compose only (the environment wins over
  # .env): .env changes once the images exist. A tag the CI has not pushed
  # yet stops here, and nothing changes.
  local vars=() p
  for p in "${targets[@]}"; do
    vars+=("$(image_var "$p")=$version")
  done
  env "${vars[@]}" docker compose pull

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

# Wrapped in main and followed by exit: bash has read the whole script before
# `git pull` can replace this file.
main "$@"
exit
