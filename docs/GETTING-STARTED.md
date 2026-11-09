# Getting started

How to run Oh-My-SSO from a fresh clone. Two ways:

| Path | For | You run |
| --- | --- | --- |
| [A. Local development](#a-local-development) | coding, debugging | databases in Docker, the Go servers and the console on your machine |
| [B. Docker Compose on a server](#b-docker-compose-on-a-server) | production | everything in containers, images from Docker Hub (`compose.example.yml`) |

## What runs

| Service | Port | Role |
| --- | --- | --- |
| `idp` (`cmd/idp`) | 8080 | public side: login pages, OIDC, SAML, account console (`/r/<realm>/account`) |
| `idp-admin` (`cmd/idp-admin`) | 8090 | Admin API + `bootstrap` / `recover` commands. Called only by the console |
| `admin` (`admin/`, Next.js) | 3000 | admin console. Signs admins in through `idp` (realm `master`) |
| PostgreSQL | 5432 | data (schema: Ent, migrations: Atlas) |
| Valkey | 6379 | sessions, rate limits, caches |
| Vault (Transit) | 8200 | signing keys and secrets encryption (`KEYMANAGER_BACKEND=vault`; production: Vault or OVH KMS) |
| Mailpit | 8025 / 1025 | catches every e-mail in development |

A **realm** is an isolated tenant (users, clients, keys). `master` is reserved for administrators and only
`idp-admin` can change it. Other realms (e.g. `demo`) hold your real users and applications.

## Prerequisites

- Docker with Compose v2
- A shell with `make` and `openssl`
- Path A only: Go 1.26+, Node 22.12+, and the [Atlas](https://atlasgo.io) CLI (`make tools` installs it,
  plus golangci-lint and govulncheck)

```bash
git clone https://github.com/DoctorPok42/Oh-My-SSO.git
cd Oh-My-SSO
make help            # every target, grouped
```

## A. Local development

### 1. Configure

```bash
cp .env.example .env                       # read by make, exported to the servers
cp admin/.env.example admin/.env.local     # console settings
```

The defaults of `.env.example` match the development stack of `make dev`: nothing to edit to start.
The Go servers read their settings **from the environment**, not from `.env`: start them with `make run` /
`make run-admin`, not with a bare `go run`.

### 2. Start the data stack and migrate

```bash
make dev
```

Starts PostgreSQL, Valkey, Vault and Mailpit, applies the migrations, enables Vault's Transit engine. The
containers are the `dev-*` services of `compose.example.yml` (profile `dev`), run as the Compose project
`oh-my-sso-dev`.
Needs `atlas` on your PATH (`make tools`).

### 3. Start the servers (one terminal each)

```bash
make run             # idp on :8080
make run-admin       # Admin API on :8090
```

### 4. Create the first administrator (once)

```bash
make admin-bootstrap email=you@example.com
```

It creates the `master` realm, the `sso-admin` client and the first admin, and prints, **once**:

1. an activation link: open it, choose a password, set up an authenticator app (MFA is mandatory for admins);
2. `OIDC_CLIENT_SECRET=...`: paste it in `admin/.env.local`.

Also set `SESSION_SECRET` in `admin/.env.local` (`openssl rand -base64 32`).
Lost the secret? `make admin-recover what=client-secret`.

### 5. Start the console

```bash
make admin-install   # first time only
make admin-dev       # http://localhost:3000
```

Sign in with the admin account. Done.

### 6. (Optional) A demo realm to try the flows

```bash
make dev-seed        # realm "demo", user alice, a role, an OIDC client; prints the password and secret
```

- Account console: <http://localhost:8080/r/demo/account/security>
- OIDC discovery: <http://localhost:8080/r/demo/.well-known/openid-configuration>
- SAML test SP: `make saml-sp` (Docker, http://localhost:8081), then `make saml-sp-register`, then open
  <http://localhost:8081/app.php>
- E-mails (activation, alerts): <http://localhost:8025>

## B. Docker Compose on a server

`compose.example.yml` and `.env.example` are the production setup: the images the CI publishes on Docker Hub, a TLS
reverse proxy in front, every setting and secret in one `.env`, `scripts/deploy.sh` to update. The full procedure
(key manager, reverse proxy, first deployment, verification, updates, backups, key rotation, pre-launch checklist)
is in **[PRODUCTION.md](PRODUCTION.md)**.

All variables are documented in `.env.example`.

## Everyday commands

| Need | Command |
| --- | --- |
| Stop / wipe the dev stack | `make docker-down` / `make docker-reset` |
| New migration after an Ent schema change | `make migrate-diff name=add_x` then `make migrate-apply` |
| psql on the dev database | `make psql` |
| Rotate a realm's signing key | `make keys-rotate realm=demo` then `make keys-retire realm=demo` |
| Unlock a user / reset their MFA | `make users-unlock …` / `make mfa-reset …` (`realm=`, `user=`, `reason=`) |
| Suspend a user, group or client | `make timeout-user` / `timeout-group` / `timeout-client` |
| Tests / full pre-commit check | `make test` / `make check` |

More options for any operation: `go run ./cmd/idp <command> --help`.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `atlas: command not found` | `make tools` (or install from atlasgo.io) |
| idp cannot reach Postgres/Vault | `make dev` not run, or run the server with `go run` instead of `make run` (the `.env` is not loaded) |
| `keys list` / signing key missing | `KEYMANAGER_BACKEND=local_dev` keeps keys in one process memory: use `vault` |
| Console: `invalid_client` / login loop | wrong `OIDC_CLIENT_SECRET`, or `OIDC_ISSUER` differs from `PUBLIC_URL/r/master` (must match exactly) |
| `make dev`: port 5432 (or 6379, 8200, 8025) already allocated | containers of the former `compose.dev.yml`: `docker rm -f postgres valkey vault mailpit` |
| Bootstrap link expired | rerun `make admin-recover what=admin email=…` |
| Lost admin secret / admin access | `make admin-recover what=client-secret` / `what=admin` (alerts every admin) |
| No e-mail received | development: <http://localhost:8025>; otherwise `make mail-test to=…` and check `SMTP_*` |
