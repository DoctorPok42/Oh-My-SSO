# Changelog

Versions follow [semantic versioning](https://semver.org). Each release lists, under **Manual steps**, what to do
by hand when updating to it. How a version is published: [docs/RELEASE.md](docs/RELEASE.md).

## [Unreleased]

## [1.1.0-rc.1] - 2026-11-27

Applications can get tokens for themselves (service to service), without a user and without a shared secret, and
tokens meant for one API only.

### Manual steps
- The database gains two columns on `client_apps` (`jwks`, `jwks_uri`), one on `tokens` (`audience`) and the
  `api_resources` tables: the `migrate` image applies them (`scripts/deploy.sh` does it and backs up first).
- Only if a client uses `jwks_uri`: `idp` needs outbound HTTPS to that address (see docs/PRODUCTION.md). Pasting the
  keys instead needs nothing.

### Added
- OAuth 2.0 `client_credentials` grant: each confidential client has a service account whose roles give the scopes of
  its tokens (`idp oidc clients create --grant client_credentials --service-role <role>`); each token is audited as
  `token.issued` and limited per client (`RATE_LIMIT_CLIENT_CREDENTIALS`, 60/min).
- Admin console and API: a client's grant types and its service account roles (`grant_types`, `service_role_ids` on
  `/clients`); the audit log labels tokens issued to a client with the `Client` actor.
- Client authentication by key (`private_key_jwt`, RFC 7523): a client signs a one-time JWT with its own RSA key
  (RS256), registered as a JWK set or a `jwks_uri`, instead of sending a secret. Details in docs/PRODUCTION.md.
- API resources (RFC 8707): an API declared per realm with its scopes (console: API Resources; API: `/api-resources`);
  a token asked for it with `resource` has it as `aud` and only its scopes. Without `resource`, nothing changes.

## [1.0.0] - 2026-11-23

First stable release: a security policy and fuzzed parsers on top of 1.0.0-rc.6. No manual step is required.

### Added
- `SECURITY.md` (private vulnerability reporting), `CONTRIBUTING.md` and a short threat model (`docs/THREAT_MODEL.md`).
- `/.well-known/security.txt` (RFC 9116), served when `SECURITY_CONTACT` is set; 404 otherwise.
- Fuzz targets for the SAML XML parser, the SAML signature check and the CSV import, run weekly in CI (`fuzz.yml`).

### Changed

- The account console's "Sessions" page shows one row per browser instead of one per sign-in (often one with an IPv4 and one with an IPv6 address). Signing a row out also ends the older sessions of that browser.

## [1.0.0-rc.6] - 2026-11-22

Users can get a copy of their data, delete their account and change their e-mail address, and the previous address is
always told of a change.

### Manual steps
- Deleting an account now erases its names and addresses from the audit log, reports and imports (see Changed).
  Export the audit log first if the names must be kept.
- Account deletion and e-mail change by users are off by default: enable them per realm in Settings > General
  (`--account-deletion=true`, `--email-change=true`). Check first that SAML clients use the persistent NameID.

### Added
- Users can download a copy of their data as JSON (Your data, GDPR articles 15 and 20). The copy is kept 7 days.
- Users can ask to delete their account (Your data, GDPR article 17), with a 14-day delay to cancel, per realm.
  Users can change their e-mail address (Profile), confirmed on the new address, with the old one notified. Both
  are off by default.

### Changed
- When an administrator changes a user's e-mail address, the previous address is now notified, as when users
  change it themselves.
- Deleting an account erases its names and addresses from the audit log, reports and imports, and removes it
  together with its traces in one transaction.

### Fixed
- Account console > History > Account activity no longer lists what an administrator did to other accounts, nor
  what they did about nobody (an import, a bulk action), and no longer shows the name of the administrator who
  acted on the account.
- Deleting an account that another server, or its owner's request, deleted a moment before answers "not found",
  with no second `user.deleted` entry.

## [1.0.0-rc.5] - 2026-11-20

Passwords are checked against common and breached ones, and a realm can keep a history and expire them.

### Manual steps
- The Have I Been Pwned check is on for every realm: allow outbound HTTPS to `api.pwnedpasswords.com`, or turn it
  off with `idp settings set --realm <realm> --password-breach-check=false` (passwords are accepted when it does not
  answer).
- Every realm refuses the last 5 passwords of an account, starting from this update. Turn it off with
  `--password-history 0`.
- Password expiry stays off until a realm sets it, and needs e-mail.

### Added
- The 100,000 most common passwords are always refused (embedded list, no network).
- Have I Been Pwned check (k-anonymity), per realm, on by default; error `password_compromised`.
- Password history, per realm (`password_history_count`, 5 by default, 10 at most); error `password_reused`.
- Password expiry, per realm (`password_expiry_days`, 0 = never): an expired password is refused at sign-in
  (`password_expired`) and replaced with "Forgot password". Existing passwords count as changed on update day.
- Console (Settings > Security) and `idp settings` show these settings.

## [1.0.0-rc.4] - 2026-11-19

Administrators of the `master` realm sign in with a passkey or a security key only.

### Manual steps
- Every account of the `master` realm now needs a passkey or a security key. An administrator with only an
  authenticator app (TOTP) types its code at the next sign-in, then must add a passkey or a security key before the
  admin console opens: check that each administrator has a device for it before updating. WebAuthn only works over
  HTTPS (or `localhost`), with `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGINS` set. An administrator who loses their only
  key gets a new account with `idp-admin recover admin`: backup codes are not enough in `master` any more.

### Changed
- `master` realm: a phishing-resistant second factor (passkey or security key) is always required, whatever its
  settings, for sign-in, the admin console and step-up (audit F-19). The e-mail alert on a sign-in from a new device
  was already on by default there (security e-mails are turned on by the bootstrap).
- `idp doctor` checks WebAuthn: `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGINS` against `PUBLIC_URL`, and the stored MFA
  policies of `master` that allow no passkey or security key (they fail every sign-in they apply to; run it before
  and after the update).
- In `master`, a client or role MFA policy whose list of methods has no passkey or security key is refused when it
  is saved (`the master realm only accepts passkeys and security keys`). It could only fail every sign-in with a
  policy conflict.

### Fixed
- The bulk reset of second factors reads which accounts have one in a single query, not one per account.
- Bulk add or removal of a group or a role: one read of the selection's memberships instead of one per account, and
  each account's link to that group or role is written alone. Before, the whole list was rewritten, which could undo a
  change made to the same account at the same time. The audit entries of these bulk actions now say
  `{"group_id": ..., "added": true|false}` (or `role_id`) instead of the account's full `group_ids` / `role_ids`.
- A bulk action in the `master` realm runs after its request has answered: an administrator's token issued while it
  ran could keep a permission one of its items took away. Each item now records a change of rights before and after
  it, as a request does; when Valkey cannot record it, the item is refused (`rights_paused`) and left unchanged.

## [1.0.0-rc.3] - 2026-11-19

Automatic signing key rotation and RSA key sizes.

### Manual steps
-

### Added
- Automatic rotation of the signing key: a realm's `jwt_signing` key is rotated once it is `key_rotation_interval_days`
  old (Settings > Security > Signing key rotation; 90 by default, 0 turns it off). The check runs every 10 minutes on
  every instance, and only one of them rotates. A failure is logged as an error and retried after 15 minutes. SAML
  keys stay manual (their rotation is two-step), and so do keys of `KEYMANAGER_BACKEND=local_dev`.
- RSA key size at rotation time: 2048 (default), 3072 or 4096, with `idp keys rotate --bits`, `rsa_bits` in the
  Admin API and a **Key size** choice in the console. A rotation without a size keeps the size of the current key.

### Changed
- Existing realms get the 90-day interval. The first check runs 10 minutes after the servers start: a realm whose
  signing key is older than that is rotated then, and the old key stays published for the realm's grace period, so
  no token is refused. To keep rotating by hand, set `key_rotation_interval_days` to 0 in Settings > Security of each
  realm within those 10 minutes (the setting does not exist before the update); later, it only stops the next ones.

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