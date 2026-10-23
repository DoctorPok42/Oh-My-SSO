# ==============================================================================
# SSO — Makefile
# ==============================================================================
# Convention: each documented target has a `## ...` comment on its declaration
# line; `make help` (or `make` alone) lists them automatically via grep/awk,
# so there is no need to maintain this list manually.
# ==============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --no-print-directory
.DEFAULT_GOAL := help

# --- Overridable variables (`make run PORT=9090`, `make migrate-diff name=add_users`) ---
APP             ?= idp
PORT            ?= 8080
COMPOSE         ?= docker compose -f compose.dev.yml
GOBIN           ?= $(CURDIR)/bin

POSTGRES_USER     ?= sso
POSTGRES_PASSWORD ?= sso
POSTGRES_DB       ?= sso
POSTGRES_HOST     ?= localhost
POSTGRES_PORT     ?= 5432
DATABASE_URL      ?= postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable

VALKEY_HOST ?= localhost
VALKEY_PORT ?= 6379
VALKEY_ADDR ?= $(VALKEY_HOST):$(VALKEY_PORT)

ENT_SCHEMA_DIR    ?= ./ent/schema
MIGRATIONS_DIR    ?= file://ent/migrate/migrations
ATLAS_DEV_URL     ?= docker://postgres/16/dev?search_path=public
name              ?= unnamed_migration

# Load a local .env file if present (not versioned), without failing if absent.
-include .env
export

# ------------------------------------------------------------------------------
## help: Display this help (default target)
help:
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##? "} /^## [a-zA-Z0-9_-]+:/ {sub(/^## /, ""); split($$0, a, ":"); printf "  \033[36m%-18s\033[0m %s\n", a[1], substr($$0, length(a[1])+3)}' $(MAKEFILE_LIST) \
		| sort -u
	@echo ""
	@echo "Overridable variables: APP, PORT, DATABASE_URL, name, ATLAS_DEV_URL, ..."

# ------------------------------------------------------------------------------
# Tooling / dependencies
# ------------------------------------------------------------------------------

## tools: Install the required CLI tools (atlas, golangci-lint, govulncheck)
tools:
	@command -v atlas >/dev/null || curl -sSf https://atlasgo.sh | sh
	@command -v golangci-lint >/dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest

## tidy: Run go mod tidy
tidy:
	go mod tidy

## generate: Regenerate the Ent client from the schema (ent/schema/*.go)
generate:
	go generate ./ent/...

# ------------------------------------------------------------------------------
# Database / migrations (Ent + Atlas)
# ------------------------------------------------------------------------------

## migrate-diff: Calculate the diff between the Ent schema and existing migrations (usage: make migrate-diff name=add_users)
migrate-diff: generate
	@echo "Generating migration '$(name)'..."
	atlas migrate diff $(name) \
		--dir "$(MIGRATIONS_DIR)" \
		--to "ent://$(ENT_SCHEMA_DIR)" \
		--dev-url "$(ATLAS_DEV_URL)"

## migrate-apply: Apply pending migrations to DATABASE_URL
migrate-apply:
	@echo "Applying migrations to $(POSTGRES_DB)@$(POSTGRES_HOST):$(POSTGRES_PORT)..."
	atlas migrate apply \
		--dir "$(MIGRATIONS_DIR)" \
		--url "$(DATABASE_URL)"

## migrate-status: Display migration status (applied / pending)
migrate-status:
	atlas migrate status \
		--dir "$(MIGRATIONS_DIR)" \
		--url "$(DATABASE_URL)"

# ------------------------------------------------------------------------------
# Build / run
# ------------------------------------------------------------------------------

## build: Compile both binaries (idp, idp-admin) into ./bin
build:
	mkdir -p $(GOBIN)
	go build -o $(GOBIN)/idp       ./cmd/idp
	go build -o $(GOBIN)/idp-admin ./cmd/idp-admin

## run: Run cmd/idp locally (public auth + user panel)
run:
	@echo "Starting idp on :$(PORT)..."
	go run ./cmd/idp

## run-admin: Run cmd/idp-admin locally (Admin API on :8090, for the admin console)
run-admin:
	@echo "Starting idp-admin..."
	go run ./cmd/idp-admin

# ------------------------------------------------------------------------------
# Admin console bootstrap and break-glass (Step 14) — idp-admin only: the
# public binary (idp) refuses every change to the master realm.
# ------------------------------------------------------------------------------

email     ?=
admin_url ?= $(if $(ADMIN_PANEL_URL),$(ADMIN_PANEL_URL),http://localhost:3000)
what      ?= admin

## admin-bootstrap: First start: master realm, admin console client and first admin (usage: make admin-bootstrap email=you@example.com [admin_url=http://localhost:3000])
admin-bootstrap:
	go run ./cmd/idp-admin bootstrap --email $(email) --admin-url $(admin_url)

## admin-recover: Break-glass, interactive, alerts every admin (usage: make admin-recover what=admin email=new@example.com | make admin-recover what=client-secret)
admin-recover:
	go run ./cmd/idp-admin recover $(what) $(if $(email),--email $(email),)

# ------------------------------------------------------------------------------
# Signing keys (Step 8) — same code as the Admin API (Step 14):
# POST /api/v1/realms/{realm}/signing-keys/... Not with KEYMANAGER_BACKEND=local_dev
# (keys would live in the memory of another process): use Vault (`make dev`).
# ------------------------------------------------------------------------------

realm ?= master

## keys-list: List the signing keys of a realm (usage: make keys-list realm=master)
keys-list:
	go run ./cmd/idp keys list --realm $(realm)

## keys-rotate: Rotate the JWT signing key of a realm (usage: make keys-rotate realm=master)
keys-rotate:
	go run ./cmd/idp keys rotate --realm $(realm)

## keys-retire: Retire the keys whose grace period ended (usage: make keys-retire realm=master)
keys-retire:
	go run ./cmd/idp keys retire --realm $(realm)

# ------------------------------------------------------------------------------
# MFA (Step 9) — same code as the HTTP API. user= takes a username or an email.
# More: go run ./cmd/idp mfa --help
# ------------------------------------------------------------------------------

user   ?=
reason ?=

## mfa-list: List the MFA factors of a user (usage: make mfa-list realm=master user=alice)
mfa-list:
	go run ./cmd/idp mfa list --realm $(realm) --user $(user)

## mfa-reset: Delete every factor of a user and revoke their sessions (usage: make mfa-reset realm=master user=alice reason="lost phone")
mfa-reset:
	go run ./cmd/idp mfa reset --realm $(realm) --user $(user) --reason "$(reason)"

## mfa-policy: Show the MFA policies of a realm: realm, roles, clients (usage: make mfa-policy realm=master)
mfa-policy:
	go run ./cmd/idp mfa policy show --realm $(realm)

# ------------------------------------------------------------------------------
# Accounts, realm settings and e-mail (Step 12).
# More: go run ./cmd/idp users --help, settings --help, mail --help
# ------------------------------------------------------------------------------

to ?=

## users-status: Failed sign-ins and lock of a user (usage: make users-status realm=demo user=alice)
users-status:
	go run ./cmd/idp users status --realm $(realm) --user $(user)

## users-unlock: Clear the lockout of a user (usage: make users-unlock realm=demo user=alice)
users-unlock:
	go run ./cmd/idp users unlock --realm $(realm) --user $(user)

## settings-show: Realm settings used by Step 12: e-mails, lockout, passwords (usage: make settings-show realm=demo)
settings-show:
	go run ./cmd/idp settings show --realm $(realm)

## alerts-on: Turn on every security e-mail of a realm, suspicious sign-ins included (usage: make alerts-on realm=demo)
alerts-on:
	go run ./cmd/idp settings set --realm $(realm) --notification-email=true --suspicious-login-email=true

## mail-test: Send a test e-mail with the SMTP_* settings (usage: make mail-test to=you@example.com)
mail-test:
	go run ./cmd/idp mail test --to $(to)

## mailpit: Address of the Mailpit inbox (every e-mail sent in development lands there)
mailpit:
	@echo "Mailpit inbox: http://localhost:8025"

# ------------------------------------------------------------------------------
# OpenID Connect (Step 10) — same code as the future admin API.
# More: go run ./cmd/idp oidc --help
# ------------------------------------------------------------------------------

client ?=

## oidc-clients: List the OIDC clients of a realm (usage: make oidc-clients realm=demo)
oidc-clients:
	go run ./cmd/idp oidc clients list --realm $(realm)

## oidc-rotate-secret: Give an OIDC client a new secret (usage: make oidc-rotate-secret realm=demo client=payroll)
oidc-rotate-secret:
	go run ./cmd/idp oidc clients rotate-secret --realm $(realm) --client-id $(client)

## dev-seed: Development only: realm "demo", user alice, role and demo OIDC client (prints the password and secret)
dev-seed:
	go run ./cmd/idp dev seed

## oidc-demo: Run the demo application (relying party) on http://localhost:9000 (reads DEMO_* from .env)
oidc-demo:
	go run ./cmd/oidc-demo

# ------------------------------------------------------------------------------
# Consent screen (Step 13). client= takes a client_id (OIDC) or an entity_id
# (SAML); user= a username or an email.
# More: go run ./cmd/idp consents --help
# ------------------------------------------------------------------------------

## consent-on: Users must approve a client on the consent screen (usage: make consent-on realm=demo client=demo)
consent-on:
	go run ./cmd/idp consents set-client --realm $(realm) --client $(client) --required=true

## consent-off: Never ask for consent for a client (usage: make consent-off realm=demo client=demo)
consent-off:
	go run ./cmd/idp consents set-client --realm $(realm) --client $(client) --required=false

## consents: The applications a user approved (usage: make consents realm=demo user=alice)
consents:
	go run ./cmd/idp consents list --realm $(realm) --user $(user)

## consent-revoke: Take back a user's consent and revoke the client's tokens (usage: make consent-revoke realm=demo user=alice client=demo)
consent-revoke:
	go run ./cmd/idp consents revoke --realm $(realm) --user $(user) --client $(client) --reason "$(reason)"

# ------------------------------------------------------------------------------
# SAML 2.0 (Step 11) — same code as the future admin API.
# More: go run ./cmd/idp saml --help
# The test service provider (SimpleSAMLphp, dev/saml-sp/) runs in Docker and
# defaults to the realm created by `make dev-seed` (demo).
# ------------------------------------------------------------------------------

sp_port       ?= 8081
SAML_SP_IMAGE ?= oh-my-sso-test-sp
# What the server uses as PUBLIC_URL (see .env.example).
SAML_IDP_URL  ?= $(if $(PUBLIC_URL),$(patsubst %/,%,$(PUBLIC_URL)),http://localhost:$(PORT))

## saml-clients: List the SAML service providers of a realm (usage: make saml-clients realm=demo)
saml-clients:
	go run ./cmd/idp saml clients list --realm $(realm)

## keys-rotate-saml: SAML key rotation, step 1: new key published, not signing yet (usage: make keys-rotate-saml realm=demo)
keys-rotate-saml:
	go run ./cmd/idp keys rotate --realm $(realm) --purpose saml_signing --reason "$(reason)"

## keys-activate-saml: SAML key rotation, step 2: the pending key starts signing (usage: make keys-activate-saml realm=demo)
keys-activate-saml:
	go run ./cmd/idp keys activate --realm $(realm) --purpose saml_signing --reason "$(reason)"

## saml-sp: Run the SimpleSAMLphp test service provider on http://localhost:8081 (Docker, dev only; usage: make saml-sp [sp_port=8082])
saml-sp: realm = demo
saml-sp:
	docker build -t $(SAML_SP_IMAGE) dev/saml-sp
	docker run --rm --init --name $(SAML_SP_IMAGE)-$(sp_port) -p $(sp_port):$(sp_port) \
		--add-host=host.docker.internal:host-gateway \
		-v $(SAML_SP_IMAGE)-$(sp_port):/var/simplesamlphp/cert \
		-e SP_PORT=$(sp_port) \
		-e IDP_METADATA_URL=http://host.docker.internal:$(PORT)/r/$(realm)/saml/metadata \
		-e IDP_ENTITY_ID=$(SAML_IDP_URL)/r/$(realm)/saml/metadata \
		$(SAML_SP_IMAGE)

## saml-sp-register: Register the running test service provider, from its metadata (usage: make saml-sp-register [sp_port=8082])
saml-sp-register: realm = demo
saml-sp-register:
	go run ./cmd/idp saml clients create --realm $(realm) \
		--metadata-url http://localhost:$(sp_port)/module.php/saml/sp/metadata/default-sp \
		--name "Test SP $(sp_port)" --allow-role employees --scope saml_profile

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

## test: Unit tests only (fast, no external dependencies)
test:
	@echo "Running unit tests..."
	go test -p 1 ./... -short -race -count=1

## test-integration: Integration tests (testcontainers-go — requires Docker)
test-integration:
	@echo "Running integration tests..."
	go test -tags=integration ./internal/storage/entstore/...
	go test ./... -run Integration -race -count=1 -timeout 10m
	go test ./internal/keymanager/... -run Integration -race -count=1 -timeout 5m

## test-all: Unit + integration tests
test-all: test test-integration

## coverage: Generate a coverage report (open the HTML report if possible)
coverage:
	go test ./... -short -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html
	@echo "Report: coverage.html"

# ------------------------------------------------------------------------------
# Code quality
# ------------------------------------------------------------------------------

## lint: Run golangci-lint on the entire module
lint:
	golangci-lint run ./...

## fmt: Run gofmt + goimports
fmt:
	gofmt -l -w .
	go vet ./...

## check-core-deps: Verify internal/core stays free of HTTP, Ent and chi (Step 7 guard)
check-core-deps:
	@deps=$$(go list -deps ./internal/core/...); \
	if echo "$$deps" | grep -E '^(net/http|entgo\.io|github\.com/go-chi|sso\.internal/sso/ent)'; then \
		echo "ERROR: internal/core must not depend on the packages listed above"; exit 1; \
	fi; \
	echo "OK: internal/core does not depend on HTTP, Ent or chi"

## check-adapter-deps: Verify protocol adapters only talk to the core, never to storage (Step 10 guard)
check-adapter-deps:
	@deps=$$(go list -deps ./internal/adapters/...); \
	if echo "$$deps" | grep -E '^(entgo\.io|sso\.internal/sso/ent(/|$$)|github\.com/valkey-io|sso\.internal/sso/internal/(storage|cache|keymanager|httpserver)(/|$$))'; then \
		echo "ERROR: internal/adapters must only use internal/core (and internal/oidcstore), not the packages listed above"; exit 1; \
	fi; \
	echo "OK: internal/adapters only depend on the core"

## vuln: Scan dependencies for known vulnerabilities
vuln:
	govulncheck ./...

## check: fmt + lint + check-core-deps + check-adapter-deps + vuln + test — run before every commit/PR
check: fmt lint check-core-deps check-adapter-deps vuln test

# ------------------------------------------------------------------------------
# Development environment (Docker Compose: postgres + valkey + vault)
# ------------------------------------------------------------------------------

## docker-up: Start postgres/valkey/vault/mailpit in the background
docker-up:
	$(COMPOSE) up -d --wait
	@echo "postgres:$(POSTGRES_PORT)  valkey:6379  vault:8200 (dev mode — never in production)  mailpit: http://localhost:8025"

## docker-down: Stop the development environment (preserve volumes)
docker-down:
	$(COMPOSE) down

## docker-reset: Stop and remove volumes (fresh database on the next up)
docker-reset:
	$(COMPOSE) down -v

## docker-logs: Follow development environment logs
docker-logs:
	$(COMPOSE) logs -f

## psql: Open a psql shell for the development database
psql:
	$(COMPOSE) exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

## vault-enable-transit: Enable Transit engine on the dev Vault
vault-enable-transit:
	@$(COMPOSE) exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token \
		vault vault secrets enable transit 2>/dev/null || true

## dev: Full development environment ready for coding (docker-up + migrate-apply)
dev: docker-up migrate-apply vault-enable-transit
	@echo "Environment ready. Run 'make run' to start idp."

# ------------------------------------------------------------------------------
# Admin panel (Next.js — see admin/)
# ------------------------------------------------------------------------------

## admin-dev: Run the Next.js admin panel in development mode
admin-dev:
	cd admin && npm run dev

## admin-build: Build the admin panel for production
admin-build:
	cd admin && npm run build

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------

## clean: Remove binaries and test artifacts
clean:
	rm -rf $(GOBIN) coverage.out coverage.html

.PHONY: help tools tidy generate \
	migrate-diff migrate-apply migrate-status migrate-lint \
	build run run-admin admin-bootstrap admin-recover \
	keys-list keys-rotate keys-retire \
	mfa-list mfa-reset mfa-policy \
	oidc-clients oidc-rotate-secret dev-seed oidc-demo \
	saml-clients keys-rotate-saml keys-activate-saml saml-sp saml-sp-register \
	consent-on consent-off consents consent-revoke \
	test test-integration test-all coverage \
	lint fmt vuln check check-core-deps check-adapter-deps \
	docker-up docker-down docker-reset docker-logs psql dev \
	admin-dev admin-build \
	clean