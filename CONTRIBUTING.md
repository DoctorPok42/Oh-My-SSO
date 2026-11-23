# Contributing

Thanks for helping. Report a security flaw privately: see [SECURITY.md](SECURITY.md), not an issue.

## Before you start

- Open an issue for anything bigger than a fix, so the design is agreed before the code is written. The roadmap
  is `todo.md`; the architecture and conventions are in [AGENTS.md](AGENTS.md) (§4 architecture, §7 conventions).
- One pull request per feature or fix. Code, comments and docs are in English.

## Set up

```bash
make tools      # atlas, golangci-lint, govulncheck
make dev        # PostgreSQL, Valkey, Vault, Mailpit in Docker + migrations
make run        # idp on :8080
```

[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) covers the admin console and a first admin. `make help` lists
every command.

## Before you open the pull request

| You changed | Run |
|---|---|
| Go code | `make test`, `make lint` |
| the database or the HTTP server | `make test-integration` (needs Docker) |
| an Ent schema | `make generate`, then `make migrate-diff name=<x>` (commit the SQL and `atlas.sum`) |
| the admin console | `make admin-lint`, `make admin-test` |
| anything large | `make check` |

The same checks run in CI. Also:

- A business rule gets a unit test; SQL gets an `*_integration_test.go`; a new parser of outside data gets a fuzz
  target (see `internal/adapters/saml/fuzz_test.go`).
- Visible text goes through the i18n helpers ([docs/I18N.md](docs/I18N.md)); a new audited event goes through
  `internal/core/audit/actions.go`.
- Update `docs/` and `CHANGELOG.md` (under **Unreleased**, two sentences at most per entry) with the change.
- Commit messages in English, `feat: ...` / `fix: ...`.

By contributing you agree that your work is released under the [Apache License 2.0](LICENSE).
