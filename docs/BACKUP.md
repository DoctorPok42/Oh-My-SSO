# Backup and restore

What Oh-My-SSO keeps, where, and what you lose if it disappears.

| Lost | Consequence | Recovery |
|---|---|---|
| **PostgreSQL** | Everything durable: realms, users and their credentials, clients, sessions' history, the audit log, settings. | `scripts/restore.sh` from the last dump. What happened after the dump is lost. Without any dump: a fresh install. |
| **Key manager** (Vault Transit keys, or the OKMS domain and its certificate) | Encrypted secrets (client and provider secrets, MFA seeds) can no longer be read, and the signing keys can no longer be used: tokens already issued stop validating. The database alone does not help. | Restore the key manager from its own backup (Vault snapshot, OKMS). Without it: new keys, and every secret to enter again, every MFA to enrol again. |
| **`.env`** | The passwords the services use (`POSTGRES_PASSWORD`, `VALKEY_PASSWORD`, key manager access) and the image tags. | Back it up apart from the dumps, with the key manager's: together they decrypt the database. `backup.sh --with-env` copies it next to the dump (`sso-<date>.env`, rights `600`) if you accept that. |
| **Valkey** | Nothing durable: sessions, rate-limit counters, the realm cache and replay protection start empty. Everyone signs in again. | None needed: restart it. `restore.sh` empties it on purpose. |
| **Images** | Nothing: they are pulled again from the registry. | `scripts/deploy.sh --version <tag>`. |

## Back up

```bash
scripts/backup.sh [--label NAME] [--with-env]   # ./backups/sso-<date>[-NAME].sql.gz, the last ten are kept (BACKUP_DIR)
```

It exits 1 if postgres is not running or the dump fails: a cron job sees it. `deploy.sh` runs it before a deploy that brings migrations. Schedule it too (cron, daily), and copy `./backups/`
**off the host**: a dump on the same disk is lost with it. Back up the key manager on its own schedule.

## Restore

```bash
scripts/restore.sh backups/sso-20261114-101500.sql.gz --yes
```

It checks the dump (gzip, and that pg_dump finished writing it), backs up the current database (`before-restore`), stops `idp` and `idp-admin`, replaces the schema in
one transaction (a dump that fails leaves the database as it was), empties Valkey, then starts everything: `migrate`
brings a dump older than the code up to date. If it fails after the stop, it says so: fix the error and run `docker compose up -d`. `.env` is not put back.

## Rehearse it

`scripts/restore_test.sh` (run by the CI) backs up and restores a real PostgreSQL. It does not replace a rehearsal on
your own data: restore the last dump on a spare host, with the saved `.env` and a restored key manager, and sign in.
