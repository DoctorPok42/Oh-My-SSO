#!/usr/bin/env bash
# Restore test with a real PostgreSQL (docker compose, a throwaway project):
# backup.sh then restore.sh bring the data back, and a bad dump changes nothing.
#   scripts/restore_test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
export COMPOSE_PROJECT_NAME=sso-restore-test
trap 'cd "$work/repo" && docker compose down -v -t 1 >/dev/null 2>&1; rm -rf "$work"' EXIT

mkdir -p "$work/repo/scripts"
cp "$here/backup.sh" "$here/restore.sh" "$work/repo/scripts/"
cd "$work/repo"
echo "SECRET=1" >.env
cat >compose.yml <<'YML'
services:
  postgres:
    image: postgres:16
    environment: { POSTGRES_USER: sso, POSTGRES_PASSWORD: sso, POSTGRES_DB: sso }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U sso"], interval: 1s, retries: 30 }
  valkey:
    image: valkey/valkey:8
    command: ["valkey-server", "--requirepass", "pw"]
    environment: { VALKEY_PASSWORD: pw }
  idp:
    image: postgres:16
    command: ["sleep", "1000"]
YML

failures=0
check() {
  if [[ $2 == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; failures=$((failures + 1)); fi
}
sql() { docker compose exec -T postgres psql -U sso sso -tA -c "$1"; }

vk() { docker compose exec -T -e REDISCLI_AUTH=pw valkey valkey-cli "$@"; }
docker compose up -d --wait postgres valkey idp
# An extension in public, an enum and a foreign key: what DROP SCHEMA CASCADE and the dump must handle.
sql "CREATE EXTENSION pgcrypto; CREATE TYPE mood AS ENUM ('ok'); CREATE TABLE users (id int PRIMARY KEY, name text, m mood); CREATE TABLE sessions (user_id int REFERENCES users);
INSERT INTO users VALUES (1, 'alice', 'ok'), (2, 'bob', 'ok')" >/dev/null
vk set k v >/dev/null

scripts/backup.sh --label test >/dev/null
dump=$(ls backups/sso-*-test.sql.gz)
check "backup: dump written" "$(test -s "$dump" && echo yes)" yes
check "backup: .env not copied by default" "$(ls backups/*.env 2>/dev/null | wc -l)" 0

sql "DELETE FROM users; CREATE TABLE junk (x int)" >/dev/null
scripts/restore.sh "$dump" >/dev/null 2>&1 && status=0 || status=$?
check "restore without --yes: refused" "$status" 1
check "restore without --yes: data untouched" "$(sql 'SELECT count(*) FROM users')" 0

head -c 100 "$dump" >"$work/bad.sql.gz"
scripts/restore.sh "$work/bad.sql.gz" --yes >/dev/null 2>&1 && status=0 || status=$?
check "truncated dump: refused" "$status" 1
check "truncated dump: data untouched" "$(sql 'SELECT count(*) FROM users')" 0

scripts/restore.sh "$dump" --yes >/dev/null
check "restore: a safety backup of the replaced database" "$(ls backups/sso-*-before-restore.sql.gz | wc -l)" 1
check "restore: Valkey emptied" "$(vk dbsize)" 0
check "restore: idp started again" "$(docker compose ps --status running --services | grep -cx idp)" 1
check "restore: extension and foreign key are back" "$(sql "SELECT count(*) FROM pg_extension WHERE extname='pgcrypto'") $(sql "SELECT count(*) FROM pg_constraint WHERE contype='f'")" "1 1"
check "restore: rows are back" "$(sql 'SELECT string_agg(name, $$,$$ ORDER BY name) FROM users')" alice,bob
check "restore: what was added since is gone" "$(sql "SELECT to_regclass('junk') IS NULL")" t

if ((failures)); then echo "$failures failure(s)"; exit 1; fi
