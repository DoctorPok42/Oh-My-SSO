# Production deployment

One host with Docker Compose: `compose.example.yml` and `.env.example`, the images the CI publishes on Docker Hub,
and a TLS reverse proxy (nginx) on the host. Read [GETTING-STARTED.md](GETTING-STARTED.md) first.

## Target topology

```
internet ──443──▶ nginx on the host (TLS) ──▶ 127.0.0.1:8080  idp    https://sso.example.com
                                         └──▶ 127.0.0.1:3000  admin  https://admin.example.com  (VPN / IP allow-list)

networks of compose.yml:
  edge   172.30.20.0/24  idp, idp-admin, admin: egress (OVH KMS, SMTP). Gateway 172.30.20.1 = TRUSTED_PROXIES
  admin  172.30.10.0/24  internal: admin 172.30.10.10 ──▶ idp-admin 172.30.10.20:8090 (ADMIN_API_ALLOWED_CIDRS)
  data   internal        idp, idp-admin ──▶ postgres, valkey
```

Never published: `idp-admin` (8090), PostgreSQL, Valkey. `idp` and the console are published on `127.0.0.1` only.

Two files, in the checkout and never committed (both are in `.gitignore`), hold the whole deployment:

| File | Copied from | Holds |
| --- | --- | --- |
| `.env` (`chmod 600`) | `.env.example` | every setting and secret. `idp` and `idp-admin` read it whole; compose takes the values of the other services from it (`${...}`) |
| `compose.yml` | `compose.example.yml` | the services. No secret, one line to edit |

## 1. Prerequisites

- Docker Engine 28+ with Compose v2.33+ (`gw_priority` in `compose.example.yml`).
- Two DNS names and their certificates: `sso.example.com` (public IdP) and `admin.example.com` (console).
- nginx on the host (or as a service of `compose.yml`, section 4).
- **OVH KMS**: an OKMS domain and an access certificate (other key managers: section 2).
- An **SMTP server** with a mailbox for the IdP. `SMTP_SECURITY=none` is refused in production except to localhost.
- PostgreSQL and Valkey run in `compose.yml` (volumes `db-data`, `valkey-data`). Valkey has no password or TLS
  option: the internal `data` network is its isolation. An external PostgreSQL works too: its URL in `DATABASE_URL`,
  with `sslmode=require` or stricter.

## 2. Key manager

The IdP signs tokens and encrypts secrets (TOTP, ...) through the key manager: private keys never leave it.

**OVH KMS** (`KEYMANAGER_BACKEND=ovhkms`): in the OVHcloud manager, create an OKMS domain and an access certificate
for it. Put the certificate and its private key in `./certs/` of the checkout (mounted read-only on `/certs`; the
containers run as uid 65532, which must be able to read them), then set `OVHKMS_ENDPOINT`, `OVHKMS_DOMAIN_ID`,
`OVHKMS_CLIENT_CERT_FILE=/certs/...` and `OVHKMS_CLIENT_KEY_FILE=/certs/...` in `.env`.

**Other key managers.** OVH KMS is the one used here. Also supported: a real **Vault**
(`KEYMANAGER_BACKEND=vault`: initialised, unsealed, with its own storage and backups), with the Transit engine:

```bash
vault secrets enable transit          # the mount path must be "transit"
vault policy write oh-my-sso - <<'POLICY'
path "transit/keys/*"    { capabilities = ["create", "read", "update"] }
path "transit/sign/*"    { capabilities = ["update"] }
path "transit/encrypt/*" { capabilities = ["update"] }
path "transit/decrypt/*" { capabilities = ["update"] }
POLICY
vault token create -policy=oh-my-sso -period=768h -orphan   # -> VAULT_TOKEN
```

Set `VAULT_ADDR` and `VAULT_TOKEN` in `.env`. The servers use this static token and do not renew it: use a
**periodic token** that you renew (Vault Agent, cron) or a long-lived one, and alert before it expires, otherwise
signing stops. `local_dev` keeps the keys in memory: development only, never in production.

## 3. Configure

```bash
git clone https://github.com/DoctorPok42/Oh-My-SSO.git oh-my-sso && cd oh-my-sso
cp compose.example.yml compose.yml
cp .env.example .env && chmod 600 .env
```

**`.env`**: under each setting that differs, `.env.example` gives its production value (`# Production:`). In short:

| Settings | Production value |
| --- | --- |
| `APP_ENV` | `production` |
| `PUBLIC_URL` | `https://sso.example.com`. The console's issuer is `PUBLIC_URL/r/master` |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGINS` | `sso.example.com`, `https://sso.example.com`. Changing the RP ID later invalidates every registered passkey: choose it once |
| `POSTGRES_PASSWORD`, `POSTGRES_HOST` | `openssl rand -hex 32`, `postgres`. `DATABASE_URL` is built from them |
| `VALKEY_ADDR` | `valkey:6379` |
| `KEYMANAGER_BACKEND`, `OVHKMS_*` | `ovhkms` and the KMS access (section 2); delete the `VAULT_*` lines |
| `TRUSTED_PROXIES` | `172.30.20.1` (section 4) |
| `SMTP_*` | your mail server |
| `ADMIN_API_ALLOWED_CIDRS` | `172.30.10.10/32`: the console's address in `compose.yml` (required in production) |
| `ADMIN_PANEL_URL`, `IDP_INTERNAL_URL` | `https://admin.example.com`, `http://idp:8080` |
| `ADMIN_SESSION_SECRET` | `openssl rand -base64 32`. Changing it signs every admin out |
| `ADMIN_OIDC_CLIENT_SECRET` | empty for now: the bootstrap prints it (section 5) |
| `IMAGE_IDP`, `IMAGE_IDP_ADMIN`, `IMAGE_ADMIN` | `latest`, or a commit sha (below) |

**`compose.yml`**: one line to edit, the `extra_hosts` of `admin`: the host name of `PUBLIC_URL`. The console's
server calls the IdP at its public URL (the OIDC issuer must match exactly), through nginx on the host
(`host-gateway`) and its valid certificate. Optional, commented in the file:

- a mail server of another compose project on the same host (e.g. Mailcow): join its network, and map the host
  name of `SMTP_HOST` to its SMTP container with `extra_hosts`;
- extra languages: the `./locales` and `./admin-locales` volumes ([I18N.md](I18N.md));
- nginx as a service of the file (section 4);
- `build:` instead of `image:`, to build the images from the checkout.

The `dev-*` services at the end of the file (profile `dev`) are for local development only: they never start in
production, and you may delete them from `compose.yml`.

**Images.** Every push on `main` that passes CI publishes `doctorpok/omsso:<image>-<commit sha>` and
`doctorpok/omsso:<image>-latest`, for `idp`, `idp-admin` and `admin`. `IMAGE_IDP`, `IMAGE_IDP_ADMIN` and
`IMAGE_ADMIN` choose the tag of each image. Pin a commit (its full sha, `git rev-parse HEAD`), the same one for `idp`
and `idp-admin` at least, and keep the checkout on that commit: the `migrate` service reads its migrations from
`./ent/migrate/migrations`, they must match the code of the images. The console image has no build-time setting:
everything comes from its environment.

## 4. Reverse proxy (nginx on the host)

nginx terminates TLS and forwards to the ports `compose.yml` publishes on `127.0.0.1`.

```nginx
# /etc/nginx/conf.d/oh-my-sso.conf
server {
    listen 80;
    server_name sso.example.com admin.example.com;
    return 301 https://$host$request_uri;
}

# --- public IdP --------------------------------------------------------------
server {
    listen 443 ssl;
    http2 on;
    server_name sso.example.com;

    ssl_certificate     /etc/letsencrypt/live/sso.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sso.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 1m;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        # Overwrite, never append ($proxy_add_x_forwarded_for would keep what the client sent):
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}

# --- admin console: restricted -----------------------------------------------
server {
    listen 443 ssl;
    http2 on;
    server_name admin.example.com;

    ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    allow 203.0.113.0/24;   # your VPN / office range
    deny  all;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Then:

- **`TRUSTED_PROXIES`**: nginx reaches `idp` through its published port, so `idp` sees every request coming from the
  gateway of the network that carries its default route: `edge` (`gw_priority: 1`), gateway `172.30.20.1`. That is
  the value of `TRUSTED_PROXIES`, safe because the port is bound to `127.0.0.1`. Check it once: the audit log must
  show the clients' addresses, not a `172.x.x.1`. If it shows the gateway of another network of `idp` (e.g.
  `172.29.1.1` with a Mailcow network), add that one too. A network's gateway:
  `docker network inspect oh-my-sso_edge -f '{{(index .IPAM.Config 0).Gateway}}'`. Because nginx overwrites
  `X-Forwarded-For` with `$remote_addr`, the default header is right; use `CLIENT_IP_HEADER` only if you forward the
  address in another header.
- **Rate limits** (per client address, so `TRUSTED_PROXIES` must be right): `/token`, `/introspect` and `/revoke`
  count the requests that authenticate no client (600/min per address) and the failed secrets of a client_id
  (10/15 min per address); a client that proves its secret is never limited. The SAML endpoints allow 300 requests per
  minute per address. A refusal is `429` with `Retry-After`: applications should wait that long before retrying. The
  `RATE_LIMIT_*` variables of `.env.example` change these values.
- **The console reaches the IdP through nginx**: its `extra_hosts` sends the host name of `PUBLIC_URL` to the host.
  nginx must listen on every address (`listen 443`, as above), and the firewall must accept connections from the
  Docker networks to the host's port 443.
- Certificates: `certbot certonly --webroot` (or the DNS challenge) for both names; reload nginx after renewal
  (`nginx -s reload`). Test the config before reloading: `nginx -t`.

**nginx in `compose.yml` instead**: uncomment its service; remove the `ports:` of `idp` and `admin` and the
`extra_hosts` of `admin`; set `TRUSTED_PROXIES=172.30.20.10` (its fixed address). Its alias, the host name of
`PUBLIC_URL` on `edge` (in the commented service), lets the console reach the IdP through it. In its configuration,
`proxy_pass http://idp:8080;` and `proxy_pass http://admin:3000;`.

## 5. First deployment

```bash
docker compose pull
docker compose up -d       # migrations first, then idp, idp-admin and the console
# exec, not run: `run` would start a second idp-admin with the same fixed IP ("Address already in use")
docker compose exec idp-admin /usr/local/bin/idp-admin bootstrap --email you@example.com --admin-url https://admin.example.com
```

The bootstrap creates the `master` realm, the `sso-admin` client and the first admin, and prints, once, an activation
link and `OIDC_CLIENT_SECRET=...`. Copy the secret into `.env` as **`ADMIN_OIDC_CLIENT_SECRET`**, then
`docker compose up -d admin`: the console is recreated with it (until then it answers every request with a
configuration error). Open the activation link (it points at `https://sso.example.com`), choose the password, enrol
an authenticator app, sign in on `https://admin.example.com`.

Then create your real realm and clients from the console. Do **not** run `dev seed` (demo user and secret) or the
SAML test service provider in production.

## 6. Verify

```bash
curl -fsS https://sso.example.com/health
curl -fsS https://sso.example.com/r/master/.well-known/openid-configuration | head
docker compose run --rm idp keys list --realm master          # a signing key must be listed
docker compose run --rm idp mail test --to you@example.com    # SMTP works
docker compose run --rm idp settings set --realm <realm> --notification-email=true --suspicious-login-email=true   # security alerts
```

The issuer must read `https://sso.example.com/r/<realm>` everywhere.

## 7. Operate

- **Update**: wait for the CI of the commit to be green (its `docker` job pushes the images), back up the database
  (migrations are not automatically reversible), then:
  ```bash
  scripts/deploy.sh --package all --version <commit sha>   # or --package idp|idp-admin|admin, --version latest
  ```
  It runs `git pull --ff-only` (the migrations), pulls the images of that tag (a tag the CI has not pushed yet stops
  it there, nothing changed), writes the `IMAGE_*` lines of `.env`, then `docker compose up -d`: only the containers
  whose image or settings changed are recreated, and `migrate` applies the pending migrations before `idp` and
  `idp-admin` start. Rollback: the previous sha (only if no migration ran in between).
  Recreating `idp-admin` during a bulk action or a CSV import is safe: on `SIGTERM` it finishes the requests in flight
  (15 s at most), then the job stops **at the item it is on** (an item is never left half done), lists the items it did
  not get to as _not processed_ in its report, and writes a `bulk.interrupted` audit entry naming them (an import ends
  as _interrupted_). The container is given 30 s to do so (`stop_grace_period` of `compose.example.yml`: keep it if
  you write your own compose file; Docker's default of 10 s is too short). Start the action again on the items left. A
  process that is killed anyway leaves a job that another `idp-admin` marks as interrupted once it has been silent for
  2 minutes (a bulk action) or 10 minutes (an import); the realm takes no new one before.
- **Settings**: after a change of `.env`, `docker compose up -d` recreates the containers that use it.
- **Backups**: PostgreSQL (users, clients, audit log), e.g.
  `docker compose exec -T postgres pg_dump -U sso sso | gzip > sso-$(date +%F).sql.gz`, **and** the key manager:
  Vault's Transit keys, or the OKMS domain and its access certificate. Without the keys, encrypted secrets and signing
  keys are lost even with a good database backup. Keep a copy of `.env`. Test a restore.
- **Purge**: every hour, `idp` and `idp-admin` delete what has ended longer ago than the realm's retention (Settings >
  General > Data retention, 90 days by default): expired or revoked sessions and tokens, used or expired reset and
  activation links, sign-in attempts, remembered accounts and trusted devices unused for that long. Each row is
  deleted by one server (batches of 1000, `FOR UPDATE SKIP LOCKED`); the logs show `purge: expired data deleted` with
  the counts.
- **Audit log retention**: 1 year by default, per realm (Settings > Audit: 30 days to 10 years, or unlimited; any
  value from 30 to 3650 days through the Admin API, `audit_log_retention_days`, 0 = unlimited). **Upgrading applies the
  1-year default to every existing realm**: set Unlimited (or a longer period) before the first purge if older entries
  must stay. The same
  hourly purge then deletes the older entries of that realm (`purge: audit log entries deleted`). Shortening it deletes
  entries for good at the next pass: export the audit log first (Audit Log > Export) or rely on the database backups if
  a copy must be kept. The change itself is in the audit log (`settings.updated`).
- **Key rotation**: `docker compose run --rm idp keys rotate --realm <realm>`, wait for tokens to expire, then
  `keys retire`. SAML: `keys rotate --purpose saml_signing`, share the new metadata with service providers, then
  `keys activate --purpose saml_signing`.
- **Break-glass** (lost admin access or console secret):
  `docker compose exec idp-admin /usr/local/bin/idp-admin recover admin --email ...` or `recover client-secret` (then
  the new secret in `ADMIN_OIDC_CLIENT_SECRET` and `docker compose up -d admin`). Every admin is alerted by e-mail.
- **Logs**: `docker compose logs -f idp idp-admin`. `ADMIN_API_LOG_REQUESTS=true` logs each Admin API call with its
  duration.
- **Sizing**: Argon2id uses 64 MiB of RAM per password hash; `PASSWORD_HASH_CONCURRENCY` (default 4) caps parallel
  hashes. Each Go process opens at most 25 database connections.
- Optional `GEOIP_DB_PATH` (MaxMind / DB-IP country `.mmdb`, mounted read-only in `idp`) enables the "sign-in from a
  new country" signal.

## Pre-launch checklist

- [ ] `APP_ENV=production`, `PUBLIC_URL` in https, the startup logs show no "development only" warning
- [ ] `.env` is `chmod 600` and the only file with secrets: none in `compose.yml`
- [ ] `KEYMANAGER_BACKEND=ovhkms`, the OKMS domain and its access certificate backed up
- [ ] PostgreSQL backed up, restore tested; PostgreSQL, Valkey and the Admin API unreachable from the internet
- [ ] `TRUSTED_PROXIES` set, the audit log shows the clients' addresses; the proxy overwrites `X-Forwarded-For`
- [ ] `ADMIN_API_ALLOWED_CIDRS` = the console only; console restricted (VPN / allow-list)
- [ ] SMTP with TLS, `mail test` received, alerts enabled on each realm
- [ ] `WEBAUTHN_RP_ID` final
- [ ] `IMAGE_*` pinned to a commit sha, the checkout on the same commit
- [ ] `dev seed`, the test SAML SP, default passwords and `dev-root-token` all gone
