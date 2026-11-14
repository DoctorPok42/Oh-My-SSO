# Changelog

Versions follow [semantic versioning](https://semver.org). Each release lists, under **Manual steps**, what to do
by hand when updating to it. How a version is published: [docs/RELEASE.md](docs/RELEASE.md).

## [Unreleased]

## [1.0.0-rc.1] - 2026-11-14

First pre-release: backup, restore and the release process. Not for production yet.

### Manual steps
- `IMAGE_IDP`, `IMAGE_IDP_ADMIN`, `IMAGE_MIGRATE` and `IMAGE_ADMIN` have no `latest` default in
  `compose.example.yml` any more: compose refuses to start without them. `scripts/deploy.sh` writes them in `.env`.

### Added
- `scripts/backup.sh` and `scripts/restore.sh`, a restore test in the CI, and `docs/BACKUP.md` (what is lost if the
  database, Valkey or the key manager disappears).
- Release process: version tags, signed images with an SBOM, this changelog.
