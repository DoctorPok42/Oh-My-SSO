#!/usr/bin/env bash
# Tests of scripts/deploy.sh with a fake `docker` on the PATH: what it runs, in
# which order, and that .env is left alone when the backup fails.
#   scripts/deploy_test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/repo/scripts" "$work/bin"
cp "$here/deploy.sh" "$work/repo/scripts/deploy.sh"
touch "$work/repo/compose.yml"

# The fake logs each call. FAKE_PG_DUMP=fail makes pg_dump fail,
# FAKE_POSTGRES=down hides the postgres service.
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >>"$FAKE_LOG"
case "$*" in
  "compose ps"*) [[ ${FAKE_POSTGRES:-up} == up ]] && echo postgres ;;
  *pg_dump*) [[ ${FAKE_PG_DUMP:-ok} == ok ]] && echo "-- dump" || exit 1 ;;
esac
EOF
chmod +x "$work/bin/docker"

failures=0
check() {
  if [[ $2 == "$3" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got '$2', want '$3'"
    failures=$((failures + 1))
  fi
}

# deploy <args...>: a fresh .env each time; the exit status in $status.
# EXTRA_ENV: more lines for .env; COMPOSE: the content of compose.yml.
deploy() {
  printf 'IMAGE_IDP=old\nIMAGE_IDP_ADMIN=old\nIMAGE_MIGRATE=old\nIMAGE_ADMIN=old\n' >"$work/repo/.env"
  if [[ -n ${EXTRA_ENV:-} ]]; then
    printf '%s\n' "$EXTRA_ENV" >>"$work/repo/.env"
  fi
  printf '%s' "${COMPOSE:-}" >"$work/repo/compose.yml"
  rm -rf "$work/repo/backups"
  : >"$work/log"
  status=0
  (cd "$work/repo" && PATH="$work/bin:$PATH" FAKE_LOG="$work/log" scripts/deploy.sh "$@") >"$work/out" 2>&1 || status=$?
}
calls() { grep -c "$1" "$work/log" || true; }

deploy --package all --version new
check "all: succeeds" "$status" 0
check "all: .env updated" "$(grep -c '=new$' "$work/repo/.env")" 4
check "all: one dump" "$(ls "$work/repo/backups" | wc -l)" 1
order=$(grep -o 'pg_dump\|compose up' "$work/log" | tr '\n' ' ')
check "all: the dump comes before up" "$order" "pg_dump compose up "

FAKE_PG_DUMP=fail deploy --package all --version new
check "failed backup: exit status" "$status" 1
check "failed backup: .env untouched" "$(grep -c '=old$' "$work/repo/.env")" 4
check "failed backup: nothing recreated" "$(calls 'compose up')" 0
check "failed backup: no partial dump left" "$(ls "$work/repo/backups" 2>/dev/null | wc -l)" 0

deploy --package admin --version new
check "admin only: succeeds" "$status" 0
check "admin only: no dump" "$(calls pg_dump)" 0
check "admin only: only IMAGE_ADMIN changes" "$(grep -c '=new$' "$work/repo/.env")" 1

deploy --package idp --version new
check "idp brings migrate" "$(grep -c '^IMAGE_\(IDP\|MIGRATE\)=new$' "$work/repo/.env")" 2
check "idp: dump" "$(calls pg_dump)" 1

deploy --package all --version new --no-backup
check "--no-backup: no dump" "$(calls pg_dump)" 0
check "--no-backup: deployed" "$(calls 'compose up')" 1

FAKE_POSTGRES=down deploy --package all --version new
check "postgres not running: deployed without a dump" "$status:$(calls pg_dump):$(calls 'compose up')" "0:0:1"

# Production requires VALKEY_PASSWORD (audit B-09): checked before anything changes.
with_requirepass=$'services:\n  valkey:\n    command: ["valkey-server", "--requirepass", "${VALKEY_PASSWORD:-}"]\n'
without_requirepass=$'services:\n  valkey:\n    image: valkey/valkey:8\n'

EXTRA_ENV="APP_ENV=production" COMPOSE="$with_requirepass" deploy --package all --version new
check "production, no VALKEY_PASSWORD: refused" "$status" 1
check "production, no VALKEY_PASSWORD: nothing pulled" "$(calls 'compose pull')" 0
check "production, no VALKEY_PASSWORD: .env untouched" "$(grep -c '=old$' "$work/repo/.env")" 4

EXTRA_ENV=$'APP_ENV=production\nVALKEY_PASSWORD=' COMPOSE="$with_requirepass" deploy --package idp-admin --version new
check "production, empty VALKEY_PASSWORD: refused" "$status" 1

EXTRA_ENV=$'APP_ENV=production\nVALKEY_PASSWORD=s3cret' COMPOSE="$without_requirepass" deploy --package idp --version new
check "production, valkey without --requirepass: refused" "$status:$(calls 'compose pull')" "1:0"

EXTRA_ENV=$'APP_ENV=production\nVALKEY_PASSWORD=s3cret' COMPOSE="$with_requirepass" deploy --package all --version new
check "production with a password: deployed" "$status:$(calls 'compose up')" "0:1"

EXTRA_ENV=$'APP_ENV=production\nVALKEY_PASSWORD=s3cret' COMPOSE=$'services:\n  idp:\n    image: x\n' deploy --package idp --version new
check "production, Valkey outside compose.yml: deployed" "$status" 0

EXTRA_ENV="APP_ENV=production" COMPOSE="$with_requirepass" deploy --package admin --version new
check "production, console only: not concerned" "$status" 0

EXTRA_ENV="APP_ENV=development" COMPOSE="$without_requirepass" deploy --package all --version new
check "development: no password needed" "$status" 0

if ((failures > 0)); then
  echo "$failures failure(s)"
  exit 1
fi
