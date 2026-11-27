# Threat model

What Oh-My-SSO protects, against whom, and what it leaves to you. It is short on purpose; to report a flaw, see
[SECURITY.md](SECURITY.md).

## What is protected

- **Credentials and sessions**: passwords (hashed, checked against common and breached ones), second factors
  (TOTP, backup codes, passkeys), SSO sessions, refresh tokens.
- **Signing keys** of each realm: kept in a key manager (OVH KMS or Vault), never in the database or on disk in
  production. Tokens and assertions are only as trustworthy as these keys.
- **Personal data** of users: the database, the audit log, exports. Users can get a copy and delete their account.
- **The administrator role**: the `master` realm and the Admin API decide who can change everything else.

## Against whom

| Attacker | What we do | Where |
|---|---|---|
| Anonymous, on the internet | Rate limits on sign-in and `/token`, `/introspect`, `/revoke`; lockout; fuzzed parsers | `RATE_LIMIT_*`, `.github/workflows/fuzz.yml` |
| A user trying another user's account or realm | Realm isolation on every query; roles and permissions checked in the service layer | `AGENTS.md` §4 |
| A malicious or compromised client application | Registered redirect URIs, client authentication, consent, scopes; signed SAML requests verified against the client's certificates | `internal/adapters/saml/verify.go` |
| Someone who stole a password | Second factor; password history and expiry; notification of sensitive changes (e-mail, password) | realm settings |
| Someone who reads the database | Passwords are hashed and second-factor secrets sealed with a realm key; backups must be encrypted by you | [docs/PRODUCTION.md](docs/PRODUCTION.md) |
| A curious administrator | Every action is in the audit log, with the actor; administrators of a realm cannot change `master` | audit log |

## What is not protected

- **A compromised server or key manager.** Whoever holds the signing keys can sign anything. Restrict access to the
  host, the KMS and its client certificate.
- **A compromised administrator of the `master` realm.** They can create other administrators. Keep the group
  small and require a second factor.
- **A wrong reverse-proxy setup.** Without TLS, or with a wrong `TRUSTED_PROXIES`, rate limits and the audit log
  see the wrong address, and sessions can be stolen on the wire.
- **The applications that trust the tokens.** A client that does not check the signature, the issuer, the
  audience or the expiry of a token is open whatever the IdP does.
- **Denial of service by volume.** Rate limits slow guessing, not a flood. Use your proxy or provider for that.
- **Mail and the user's mailbox.** Password reset and e-mail change are as safe as the mailbox they go to.
- **Phishing.** Passkeys resist it; passwords and codes do not.

## Where outside data is parsed

SAML messages and signatures, the CSV of an import, and OIDC requests are the parts that read bytes an attacker
controls. The first two have fuzz targets, run weekly in CI. OIDC requests include the `client_assertion` JWTs of
`private_key_jwt` clients, sent by anyone to `/token`, `/introspect` and `/revoke` and checked by the OIDC library,
and the JWK sets read from a client's `jwks_uri` (64 KiB at most).

## Outbound requests

A realm administrator chooses the `jwks_uri` of a `private_key_jwt` client: `idp` then calls that URL, so it could
be aimed at the server's own network. Only https to a public address is called (checked when connecting, IPv4 inside
IPv6 included), without redirect, for 5 seconds at most and once a minute at most per URL; the answer is never shown
to the caller. Details in [PRODUCTION.md](PRODUCTION.md) ("Clients without a secret").
