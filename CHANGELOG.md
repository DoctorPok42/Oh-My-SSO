# Changelog

Versions follow [semantic versioning](https://semver.org). Each release lists, under **Manual steps**, what to do
by hand when updating to it. How a version is published: [docs/RELEASE.md](docs/RELEASE.md).

## [Unreleased]

## [1.0.0-rc.2] - 2026-11-19

Logs, metrics and diagnostics.

### Manual steps
- `compose.yml`: copy the `x-logging` block of `compose.example.yml` and its `logging: *logging` line into each
  service, then `docker compose up -d` (it recreates the containers). `idp` now writes one line per request, and
  Docker keeps container logs without a size limit by default. Instead, a host-wide limit: `log-opts` in
  `/etc/docker/daemon.json`.

### Added
- Structured logs for `idp` and `idp-admin`: `LOG_FORMAT=json` (one object per line; default `text`) and
  `LOG_LEVEL` (`debug`, `info`, `warn`, `error`; default `info`).
- Access log of the public server: one line per request (method, path without its query string, status, duration,
  realm, client address); `/health` and `/readyz` at the debug level.
- Request ID on every log line of a request and in the audit entries it writes (`details.request_id`). A proxy's
  `X-Request-Id` is kept when it looks like an ID (at most 64 letters, digits, `.`, `_`, `:` or `-`).
- A handler that panics is logged as one error line with its stack and request ID (before: a text stack trace on
  stderr, outside the log format).
- `compose.example.yml` caps the logs Docker keeps for each service: 5 files of 50 MB.
- Prometheus metrics on `METRICS_ADDR` (e.g. `:9100`; unset: none), a listener of its own on `idp` and
  `idp-admin`: request duration by route, audit events (sign-ins, failures, lockouts…), tokens issued, the status of
  PostgreSQL, Valkey, the key manager and SMTP (`omsso_dependency_up`), Go runtime and process metrics.
- `idp doctor`: checks every setting and dependency at once (database and schema, clock drift, Valkey, key manager
  signature, SMTP sign-in, SPF / DKIM, `PUBLIC_URL` and its TLS certificate, `TRUSTED_PROXIES`, GeoIP database),
  one line each; exit status 1 when one fails.

### Changed
- The startup lines go through `slog` with a level (`WARN` for a development-only setting, `ERROR` before a
  refused start) instead of Go's `log` package: their format changed, `time=… level=… msg=…` in text.
- `KEYMANAGER_BACKEND=local_dev` (or unset) with `APP_ENV=production` stops the servers with an error line instead
  of a panic.

## [1.0.0-rc.1] - 2026-11-14

First pre-release: backup, restore and the release process. Not for production yet.

### Manual steps
- `IMAGE_IDP`, `IMAGE_IDP_ADMIN`, `IMAGE_MIGRATE` and `IMAGE_ADMIN` have no `latest` default in
  `compose.example.yml` any more: compose refuses to start without them. `scripts/deploy.sh` writes them in `.env`.

### Added
- `scripts/backup.sh` and `scripts/restore.sh`, a restore test in the CI, and `docs/BACKUP.md` (what is lost if the
  database, Valkey or the key manager disappears).
- Release process: version tags, signed images with an SBOM, this changelog.
