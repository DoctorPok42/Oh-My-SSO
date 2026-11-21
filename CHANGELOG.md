# Changelog

Versions follow [semantic versioning](https://semver.org). Each release lists, under **Manual steps**, what to do
by hand when updating to it. How a version is published: [docs/RELEASE.md](docs/RELEASE.md).

## [Unreleased]

### Manual steps
- Deleting an account now erases what still names it (see Changed): the audit log keeps its entries under the
  account's id, without its name, e-mail address or network addresses. Export the audit log first if a copy with
  names must be kept for the accounts you delete.
- Users cannot delete their own account until a realm turns it on (Settings > General, or
  `idp settings set --realm <realm> --account-deletion=true`).
- Users cannot change their e-mail address until a realm turns it on (Settings > General, or
  `idp settings set --realm <realm> --email-change=true`). Before that, move the SAML clients that use the
  `emailAddress` NameID to `persistent`, and check that the OIDC applications match accounts by `sub`: an
  application that matches them by address sees a new user after a change.

### Added
- Account console > Your data: a user downloads a copy of their data (GDPR articles 15 and 20), as JSON. It is made
  in the background, announced by e-mail (`data_export_ready`), downloadable for 7 days after confirming it's them,
  then purged. Its sign-in history and audit entries keep the 10 000 newest rows each (`truncated` names a list
  cut); the audit entries are those about the account, without the names of the administrators. New table
  `data_exports` (migration `20261120214519_data_export`); audit actions `user.data_export_requested` and
  `user.data_exported`.
- Account deletion by its owner (GDPR article 17), per realm (`account_deletion_enabled`, off by default, never in
  `master`): from Your data, after confirming it's them, the account is signed out everywhere and deleted 14 days
  later by the hourly purge. In between, applications refuse it (OIDC `access_denied`, SAML `RequestDenied`, a page
  in the browser), and the user may sign in to the account console and keep it; an administrator may also cancel
  (user drawer, `POST /users/{id}/deletion/cancel`). E-mail `account_deletion_scheduled`; audit actions
  `user.deletion_requested` and `user.deletion_cancelled`; badge "Deletion scheduled" in the console. Migration
  `20261120225941_account_deletion`.
- E-mail change by the user, per realm (`email_change_allowed`, off by default): from the account console
  (Profile), after confirming it's them. The new address waits in `users.pending_email` until the link e-mailed to
  it is opened: applications never see an unproven address. Then the account switches to it, verified, and the
  previous address gets the e-mail `email_changed`. An administrator's change, a new request or a verification
  e-mail cancels a pending change. Audit actions `user.email_change_requested`, `user.email_changed`,
  `user.email_change_cancelled`; the admin console warns about the `emailAddress` NameID. Needs e-mail: the
  setting is refused without SMTP. Migration `20261121100000_email_change`.

### Changed
- Deleting an account (administrator, bulk action, or its owner) removes it and erases its traces in one
  transaction (a deletion its owner cancelled at the last moment does not happen): its sign-in attempts are deleted;
  in the audit log, the addresses and browsers of what it did (and of the sign-ins made with its name) are cleared
  and its username and e-mail address become `[deleted]`, in the details too (in the entries about it, also the
  names and addresses it had or asked for and the recipients of its e-mails); the same in the reports of bulk
  actions and user imports. `user.deleted` keeps the id, the reason and the applications that received the
  account's data (to tell them, GDPR article 19), no longer the username and e-mail address. `user.import_finished`
  now lists the id of each account created, so that a later deletion finds it there whatever its name then; entries
  written before keep a name or address the account changed since. Suspensions (Timeouts) of a deleted account are
  kept with their reason.
- A password reset link e-mailed to an address the account no longer has stops working (its owner or an
  administrator changed the address): whoever reads the old mailbox may not be the owner any more.

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