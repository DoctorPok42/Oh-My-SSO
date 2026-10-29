#!/usr/bin/env bash
# End-to-end tests of the admin console against a throw-away stack:
#   fresh database -> migrations -> idp-admin bootstrap -> idp + idp-admin
#   -> console (production build, by Playwright) -> tests.
#
# Needs `make dev` running (PostgreSQL, Valkey, Vault with Transit), Go, and
# Playwright's Chromium (`cd admin && npx playwright install chromium`).
# Ports 8180 / 8190 / 3100: no clash with a development stack on 8080 / 8090 / 3000.
#
#   make admin-e2e                 # everything
#   make admin-e2e args="-g realm" # only the tests whose title matches
#
# Overrides: E2E_DATABASE_URL, E2E_RESET_DB (a command that empties and
# migrates the database), VAULT_ADDR, VAULT_TOKEN, VALKEY_ADDR.
set -euo pipefail
cd "$(dirname "$0")/../.." # repository root

STATE=admin/e2e/.state
rm -rf "$STATE" && mkdir -p "$STATE"
DB_URL=${E2E_DATABASE_URL:-postgres://sso:sso@localhost:5432/sso_e2e?sslmode=disable}

echo "==> fresh database"
if [[ -n "${E2E_RESET_DB:-}" ]]; then
  eval "$E2E_RESET_DB"
else
  db=$(sed -E 's|.*/([^/?]+)(\?.*)?$|\1|' <<<"$DB_URL")
  docker compose -f compose.dev.yml exec -T postgres psql -v ON_ERROR_STOP=1 -U sso -d postgres \
    -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" -c "CREATE DATABASE \"$db\""
  atlas migrate apply --dir file://ent/migrate/migrations --url "$DB_URL"
fi

export DATABASE_URL=$DB_URL APP_ENV=development \
  KEYMANAGER_BACKEND=vault VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200} VAULT_TOKEN=${VAULT_TOKEN:-dev-root-token} \
  VALKEY_ADDR=${VALKEY_ADDR:-127.0.0.1:6379} \
  PORT=8180 PUBLIC_URL=http://localhost:8180 \
  ADMIN_API_ADDR=127.0.0.1:8190 ADMIN_API_ALLOWED_CIDRS=127.0.0.1/32 ADMIN_PANEL_URL=http://localhost:3100 \
  IDP_INTERNAL_URL=http://localhost:8180 \
  WEBAUTHN_RP_ID=localhost WEBAUTHN_RP_ORIGINS=http://localhost:8180 \
  SMTP_HOST= # no SMTP: e-mails are printed in the logs

echo "==> build idp, idp-admin"
go build -o "$STATE/idp" ./cmd/idp
go build -o "$STATE/idp-admin" ./cmd/idp-admin

echo "==> bootstrap"
"$STATE/idp-admin" bootstrap --email e2e-admin@example.test --admin-url http://localhost:3100 >"$STATE/bootstrap.txt"

echo "==> start idp (:8180) and idp-admin (:8190)"
"$STATE/idp" >"$STATE/idp.log" 2>&1 &
IDP_PID=$!
"$STATE/idp-admin" serve >"$STATE/idp-admin.log" 2>&1 &
ADMIN_PID=$!
trap 'kill $IDP_PID $ADMIN_PID 2>/dev/null || true' EXIT
for url in http://localhost:8180/health http://127.0.0.1:8190/health; do
  for _ in $(seq 1 60); do curl -fsS "$url" >/dev/null 2>&1 && break || sleep 0.5; done
  curl -fsS "$url" >/dev/null || { echo "not ready: $url (see $STATE/*.log)"; exit 1; }
done

echo "==> console + Playwright"
export OIDC_ISSUER=http://localhost:8180/r/master OIDC_CLIENT_ID=sso-admin \
  OIDC_CLIENT_SECRET="$(sed -nE 's/^ *OIDC_CLIENT_SECRET=(.*)$/\1/p' "$STATE/bootstrap.txt")" \
  ADMIN_URL=http://localhost:3100 ADMIN_API_URL=http://127.0.0.1:8190 \
  SESSION_SECRET="$(openssl rand -base64 32)" DEFAULT_REALM=master \
  E2E_BASE_URL=http://localhost:3100 E2E_BOOTSTRAP_OUTPUT="$PWD/$STATE/bootstrap.txt" CI=${CI:-1}
cd admin
npx playwright test "$@"
