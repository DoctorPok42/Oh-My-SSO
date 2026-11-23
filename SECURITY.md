# Security policy

## Reporting a vulnerability

Please report it privately, not in a public issue:

1. Go to [Report a vulnerability](https://github.com/DoctorPok42/Oh-My-SSO/security/advisories/new) (the
   repository's **Security** tab, GitHub private vulnerability reporting).
2. Say which version you ran (`idp` image tag), what you did, what happened and what you expected. A minimal
   reproduction helps most.

We acknowledge reports, work on a fix, and agree a disclosure date with you. Nothing is published before a fixed
release exists, unless the flaw is already being exploited.

## Supported versions

Fixes land in the latest release (`CHANGELOG.md`). Update with the **Manual steps** of each version
([docs/RELEASE.md](docs/RELEASE.md), [docs/PRODUCTION.md](docs/PRODUCTION.md)).

## Scope

In scope: this repository: `idp` (OIDC and SAML provider, account console), `idp-admin` (Admin API), the admin
console (`admin/`), the Docker images and the example deployment (`compose.example.yml`, `.env.example`).

Out of scope: a deployment that ignores [docs/PRODUCTION.md](docs/PRODUCTION.md) (no TLS, `TRUSTED_PROXIES` wrong,
secrets in the repository), denial of service by raw traffic volume, missing hardening headers with no
demonstrated impact, and flaws in a dependency that do not affect Oh-My-SSO (report those upstream).
What is protected, against whom, and what is not: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Do not test against a server you do not operate, and do not read or change other people's data: a proof that
you could is enough.

## For operators

`GET /.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)) tells your own users and
researchers whom to contact about *your* instance. Set `SECURITY_CONTACT` (an address, a `mailto:` or an `https:`
URL) in `.env` to turn it on. Without it, the route answers 404.
