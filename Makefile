# ==============================================================================
# Oh-My-SSO — Makefile.  `make` or `make help` lists every target.
# A target is documented by a `## name: description` line above it; a
# `##@ Title` line starts a new section of the help.
# ==============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --no-print-directory
.DEFAULT_GOAL := help

# --- Variables (override on the command line: `make run PORT=9090`) -----------
PORT              ?= 8080
# Development data stack: the "dev" profile of compose.example.yml, as its own
# project (never the volumes of a production stack).
COMPOSE           ?= docker compose -f compose.example.yml -p oh-my-sso-dev --profile dev
DEV_SERVICES      ?= dev-postgres dev-valkey dev-vault dev-mailpit
GOBIN             ?= $(CURDIR)/bin

POSTGRES_USER     ?= sso
POSTGRES_PASSWORD ?= sso
POSTGRES_DB       ?= sso
POSTGRES_HOST     ?= localhost
POSTGRES_PORT     ?= 5432
DATABASE_URL      ?= postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)?sslmode=disable
VALKEY_ADDR       ?= localhost:6379
VAULT_TOKEN       ?= dev-root-token

ENT_SCHEMA_DIR    ?= ./ent/schema
MIGRATIONS_DIR    ?= file://ent/migrate/migrations
ATLAS_DEV_URL     ?= docker://postgres/16/dev?search_path=public

# Arguments of the CLI targets (`make users-unlock realm=demo user=alice`)
realm     ?= master
user      ?=
client    ?=
group     ?=
id        ?=
to        ?=
reason    ?=
duration  ?=
email     ?=
what      ?= admin
name      ?= unnamed_migration
args      ?=
admin_url ?= $(or $(ADMIN_PANEL_URL),http://localhost:3000)
sp_port   ?= 8081

SAML_SP_IMAGE ?= oh-my-sso-test-sp
SAML_IDP_URL  ?= $(patsubst %/,%,$(or $(PUBLIC_URL),http://localhost:$(PORT)))

# Load a local .env (not versioned) and export it to every command.
-include .env
export

IDP   := go run ./cmd/idp
ADMIN := go run ./cmd/idp-admin

.PHONY: help tools tidy generate \
	dev docker-up docker-down docker-reset docker-logs mailpit psql vault-enable-transit \
	migrate-diff migrate-apply migrate-status \
	build run run-admin admin-bootstrap admin-recover \
	admin-install admin-dev admin-build admin-lint admin-test admin-e2e docker-build \
	dev-seed oidc-clients oidc-rotate-secret \
	keys-list keys-rotate keys-retire keys-rotate-saml keys-activate-saml \
	saml-clients saml-sp saml-sp-register \
	mfa-list mfa-reset mfa-policy \
	users-status users-unlock settings-show alerts-on mail-test mail-preview \
	consent-on consent-off consents consent-revoke \
	timeouts timeout-user timeout-group timeout-client timeout-lift \
	test test-integration test-all coverage lint fmt vuln \
	check-core-deps check-adapter-deps check clean

help:
	@awk '/^##@ / {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} \
		/^## [a-zA-Z0-9_-]+: / {n = index($$0, ":"); printf "  \033[36m%-20s\033[0m %s\n", substr($$0, 4, n-4), substr($$0, n+2)}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Variables: PORT, DATABASE_URL, realm, user, client, ... (make <target> realm=demo user=alice)"

##@ Setup

## tools: Install the CLI tools (atlas, golangci-lint, govulncheck)
tools:
	@command -v atlas >/dev/null || curl -sSf https://atlasgo.sh | sh
	@command -v golangci-lint >/dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest

## tidy: go mod tidy
tidy:
	go mod tidy

## generate: Regenerate the Ent client from ent/schema
generate:
	go generate ./ent/...

##@ Development stack (Docker: postgres, valkey, vault, mailpit; profile dev of compose.example.yml)

## dev: Everything needed to code: containers up, migrations applied, Vault Transit enabled
dev: docker-up migrate-apply vault-enable-transit
	@echo "Ready. Next: make run (idp), make admin-bootstrap email=you@example.com (first time)."

## docker-up: Start the containers in the background (mailpit inbox: http://localhost:8025)
docker-up:
	$(COMPOSE) up -d --wait $(DEV_SERVICES)

## docker-down: Stop the containers (keep the data)
docker-down:
	$(COMPOSE) down

## docker-reset: Stop the containers and delete the data (fresh database next time)
docker-reset:
	$(COMPOSE) down -v

## docker-logs: Follow the containers' logs
docker-logs:
	$(COMPOSE) logs -f

## mailpit: Address of the Mailpit inbox (every e-mail sent in development lands there)
mailpit:
	@echo "Mailpit inbox: http://localhost:8025"

## psql: Open psql on the development database
psql:
	$(COMPOSE) exec dev-postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

## vault-enable-transit: Enable the Transit engine on the dev Vault (idempotent)
vault-enable-transit:
	@$(COMPOSE) exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=$(VAULT_TOKEN) \
		dev-vault vault secrets enable transit 2>/dev/null || true

##@ Database (Ent + Atlas)

## migrate-diff: Generate a migration from the Ent schema (make migrate-diff name=add_users)
migrate-diff: generate
	atlas migrate diff $(name) --dir "$(MIGRATIONS_DIR)" --to "ent://$(ENT_SCHEMA_DIR)" --dev-url "$(ATLAS_DEV_URL)"

## migrate-apply: Apply the pending migrations to the database
migrate-apply:
	atlas migrate apply --dir "$(MIGRATIONS_DIR)" --url "$(DATABASE_URL)"

## migrate-status: Show applied / pending migrations
migrate-status:
	atlas migrate status --dir "$(MIGRATIONS_DIR)" --url "$(DATABASE_URL)"

##@ Run

## build: Build idp and idp-admin into ./bin
build:
	mkdir -p $(GOBIN)
	go build -o $(GOBIN)/idp       ./cmd/idp
	go build -o $(GOBIN)/idp-admin ./cmd/idp-admin

## run: Run idp (login, OIDC, SAML, account panel) on :8080
run:
	$(IDP)

## run-admin: Run idp-admin (Admin API on :8090)
run-admin:
	$(ADMIN)

## admin-bootstrap: First start: master realm, console client, first admin (make admin-bootstrap email=you@example.com)
admin-bootstrap:
	$(ADMIN) bootstrap --email $(email) --admin-url $(admin_url)

## admin-recover: Break-glass, alerts every admin (what=admin email=new@example.com | what=client-secret | what=timeouts)
admin-recover:
	$(ADMIN) recover $(what) $(if $(email),--email $(email),)

##@ Admin console (Next.js, admin/)

## admin-install: Install the dependencies (npm ci)
admin-install:
	cd admin && npm ci

## admin-dev: Run the console in dev mode on :3000 (reads admin/.env.local)
admin-dev:
	cd admin && npm run dev

## admin-build: Production build
admin-build:
	cd admin && npm run build

## admin-lint: ESLint + Prettier + TypeScript
admin-lint:
	cd admin && npm run lint && npm run typecheck

## admin-test: Unit tests (Vitest)
admin-test:
	cd admin && npm test

## admin-e2e: End-to-end tests on a throw-away stack, needs `make dev` (make admin-e2e [args="-g realm"])
admin-e2e:
	admin/e2e/run.sh $(args)

## docker-build: Build the three production images (idp, idp-admin, admin)
docker-build:
	docker build --target idp -t oh-my-sso-idp .
	docker build --target idp-admin -t oh-my-sso-idp-admin .
	docker build -t oh-my-sso-admin ./admin

##@ Operations: OIDC, keys, SAML (more: go run ./cmd/idp <command> --help)

## dev-seed: DEV ONLY: realm "demo", user alice, role, demo OIDC client (prints password and secret)
dev-seed:
	$(IDP) dev seed

## oidc-clients: List the OIDC clients of a realm
oidc-clients:
	$(IDP) oidc clients list --realm $(realm)

## oidc-rotate-secret: New secret for an OIDC client (make oidc-rotate-secret realm=demo client=payroll)
oidc-rotate-secret:
	$(IDP) oidc clients rotate-secret --realm $(realm) --client-id $(client)

## keys-list: List the signing keys of a realm (needs the vault backend)
keys-list:
	$(IDP) keys list --realm $(realm)

## keys-rotate: Rotate the JWT signing key of a realm
keys-rotate:
	$(IDP) keys rotate --realm $(realm)

## keys-retire: Retire the keys whose grace period ended
keys-retire:
	$(IDP) keys retire --realm $(realm)

## keys-rotate-saml: SAML key rotation, step 1: publish a new key, not signing yet
keys-rotate-saml:
	$(IDP) keys rotate --realm $(realm) --purpose saml_signing --reason "$(reason)"

## keys-activate-saml: SAML key rotation, step 2: the pending key starts signing
keys-activate-saml:
	$(IDP) keys activate --realm $(realm) --purpose saml_signing --reason "$(reason)"

## saml-clients: List the SAML service providers of a realm
saml-clients:
	$(IDP) saml clients list --realm $(realm)

## saml-sp: DEV ONLY: SimpleSAMLphp test service provider in Docker on :8081, realm demo (sp_port=8082)
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

## saml-sp-register: DEV ONLY: register the running test service provider from its metadata
saml-sp-register: realm = demo
saml-sp-register:
	$(IDP) saml clients create --realm $(realm) \
		--metadata-url http://localhost:$(sp_port)/module.php/saml/sp/metadata/default-sp \
		--name "Test SP $(sp_port)" --allow-role employees --scope saml_profile

##@ Operations: users, MFA, e-mail, consent, timeouts (user= takes a username or an e-mail)

## mfa-list: List the MFA factors of a user
mfa-list:
	$(IDP) mfa list --realm $(realm) --user $(user)

## mfa-reset: Delete a user's factors and revoke their sessions (reason="lost phone")
mfa-reset:
	$(IDP) mfa reset --realm $(realm) --user $(user) --reason "$(reason)"

## mfa-policy: Show the MFA policies of a realm
mfa-policy:
	$(IDP) mfa policy show --realm $(realm)

## users-status: Failed sign-ins and lock of a user
users-status:
	$(IDP) users status --realm $(realm) --user $(user)

## users-unlock: Clear the lockout of a user
users-unlock:
	$(IDP) users unlock --realm $(realm) --user $(user)

## settings-show: Realm settings (e-mails, lockout, passwords)
settings-show:
	$(IDP) settings show --realm $(realm)

## alerts-on: Turn on every security e-mail of a realm
alerts-on:
	$(IDP) settings set --realm $(realm) --notification-email=true --suspicious-login-email=true

## mail-test: Send a test e-mail with the SMTP_* settings (make mail-test to=you@example.com)
mail-test:
	$(IDP) mail test --to $(to)

## mail-preview: Send every e-mail template with sample data, to review them (and their HTML Check score) in Mailpit (make mail-preview to=you@example.com)
mail-preview:
	$(IDP) mail test --to $(to) --all

## consent-on: Require the consent screen for a client (client_id or SAML entity_id)
consent-on:
	$(IDP) consents set-client --realm $(realm) --client $(client) --required=true

## consent-off: Never ask for consent for a client
consent-off:
	$(IDP) consents set-client --realm $(realm) --client $(client) --required=false

## consents: The applications a user approved
consents:
	$(IDP) consents list --realm $(realm) --user $(user)

## consent-revoke: Take back a user's consent and revoke the client's tokens
consent-revoke:
	$(IDP) consents revoke --realm $(realm) --user $(user) --client $(client) --reason "$(reason)"

## timeouts: Scheduled and active timeouts of a realm
timeouts:
	$(IDP) timeouts list --realm $(realm)

## timeout-user: Suspend a user now (reason="investigation" [duration=24h])
timeout-user:
	$(IDP) timeouts create --realm $(realm) --user $(user) --reason "$(reason)" $(if $(duration),--for $(duration),)

## timeout-group: Suspend every member of a group ([duration=7d])
timeout-group:
	$(IDP) timeouts create --realm $(realm) --group $(group) --reason "$(reason)" $(if $(duration),--for $(duration),)

## timeout-client: Suspend an application for everybody ([duration=2h])
timeout-client:
	$(IDP) timeouts create --realm $(realm) --client $(client) --reason "$(reason)" $(if $(duration),--for $(duration),)

## timeout-lift: End a timeout now (id= from `make timeouts`)
timeout-lift:
	$(IDP) timeouts lift --realm $(realm) --id $(id)

##@ Tests and quality

## test: Unit tests (fast, no dependency)
test:
	go test -p 1 ./... -short -race -count=1

## test-integration: Integration tests (testcontainers, needs Docker)
test-integration:
	go test -tags=integration ./internal/storage/entstore/...
	go test ./... -run Integration -race -count=1 -timeout 10m
	go test ./internal/keymanager/... -run Integration -race -count=1 -timeout 5m

## test-all: Unit + integration tests
test-all: test test-integration

## coverage: Coverage report (coverage.html)
coverage:
	go test ./... -short -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

## lint: golangci-lint
lint:
	golangci-lint run ./...

## fmt: gofmt + go vet
fmt:
	gofmt -l -w .
	go vet ./...

## vuln: Scan the dependencies for known vulnerabilities
vuln:
	govulncheck ./...

## check-core-deps: internal/core must stay free of HTTP, Ent and chi
check-core-deps:
	@deps=$$(go list -deps ./internal/core/...); \
	if echo "$$deps" | grep -E '^(net/http|entgo\.io|github\.com/go-chi|sso\.internal/sso/ent)'; then \
		echo "ERROR: internal/core must not depend on the packages listed above"; exit 1; \
	fi; \
	echo "OK: internal/core does not depend on HTTP, Ent or chi"

## check-adapter-deps: Protocol adapters may only use the core, never storage
check-adapter-deps:
	@deps=$$(go list -deps ./internal/adapters/...); \
	if echo "$$deps" | grep -E '^(entgo\.io|sso\.internal/sso/ent(/|$$)|github\.com/valkey-io|sso\.internal/sso/internal/(storage|cache|keymanager|httpserver)(/|$$))'; then \
		echo "ERROR: internal/adapters must only use internal/core (and internal/oidcstore)"; exit 1; \
	fi; \
	echo "OK: internal/adapters only depend on the core"

## check: fmt + lint + dependency guards + vuln + test: run before every commit
check: fmt lint check-core-deps check-adapter-deps vuln test

## clean: Remove binaries and test artifacts
clean:
	rm -rf $(GOBIN) coverage.out coverage.html
	rm -rf admin/.next admin/test-results admin/playwright-report admin/e2e/.state
