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

## run-admin: Run cmd/idp-admin locally (Admin API)
run-admin:
	@echo "Starting idp-admin..."
	go run ./cmd/idp-admin

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

## test: Unit tests only (fast, no external dependencies)
test:
	@echo "Running unit tests..."
	go test ./... -short -race -count=1

## test-integration: Integration tests (testcontainers-go — requires Docker)
test-integration:
	@echo "Running integration tests..."
	go test -tags=integration ./internal/storage/entstore/...
	go test ./... -run Integration -race -count=1 -timeout 5m

## test-ovhkms: Integration tests for the OVH KMS key manager (requires Docker + OVH credentials)
test-ovhkms:
	go test ./internal/keymanager/ovhkms/... -run Integration -v

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

## vuln: Scan dependencies for known vulnerabilities
vuln:
	govulncheck ./...

## check: fmt + lint + vuln + test — run before every commit/PR
check: fmt lint vuln test

# ------------------------------------------------------------------------------
# Development environment (Docker Compose: postgres + valkey + vault)
# ------------------------------------------------------------------------------

## docker-up: Start postgres/valkey/vault in the background
docker-up:
	$(COMPOSE) up -d --wait
	@echo "postgres:$(POSTGRES_PORT)  valkey:6379  vault:8200 (dev mode — never in production)"

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
	build run run-admin \
	test test-integration test-all coverage \
	lint fmt vuln check \
	docker-up docker-down docker-reset docker-logs psql dev \
	admin-dev admin-build \
	clean