# Oh-My-SSO — admin console

Next.js (App Router) console to administer Oh-My-SSO: realms, OIDC and SAML clients, client scopes,
sessions, audit log, users / roles / groups / permissions, signing keys, MFA policies, settings.

It is a **BFF** (Backend For Frontend): the browser only talks to this server. This server signs the
admin in with OpenID Connect (client `sso-admin` of the `master` realm), keeps the tokens in an
encrypted, `HttpOnly` cookie, and calls the Admin API (`cmd/idp-admin`) on the admin network. The
browser never sees a token and never reaches the Admin API.

```
browser ──https──▶ admin console (this app) ──Bearer JWT──▶ idp-admin (Admin API, :8090)
   │                     │
   └──── sign-in ───▶ idp (OIDC, :8080) ◀── code exchange, refresh ──┘
```

## Start (development)

```bash
make dev                                   # PostgreSQL, Valkey, Vault, Mailpit
make admin-bootstrap email=you@example.com # once: prints OIDC_CLIENT_SECRET and an activation link
make run          # terminal 1: idp on :8080
make run-admin    # terminal 2: Admin API on :8090
cp admin/.env.example admin/.env.local     # paste OIDC_CLIENT_SECRET, set SESSION_SECRET
make admin-install && make admin-dev       # terminal 3: http://localhost:3000
```

Open the activation link, choose the password, add an authenticator app, then sign in on
http://localhost:3000.

## Scripts

| Command             | What it does                                                     |
| ------------------- | ---------------------------------------------------------------- |
| `npm run dev`       | development server (hot reload) on :3000                         |
| `npm run build`     | production build (`.next/standalone`)                            |
| `npm run lint`      | ESLint + Prettier check                                          |
| `npm run typecheck` | TypeScript                                                       |
| `npm test`          | unit tests (Vitest, `tests/`)                                    |
| `make admin-e2e`    | end-to-end tests (Playwright, `e2e/`) on a throw-away stack      |
| `make docker-build` | images `oh-my-sso-idp`, `oh-my-sso-idp-admin`, `oh-my-sso-admin` |

## Layout

```
src/
  proxy.ts              every request: CSP nonce, session check, token refresh
  app/
    auth/               login, callback, step-up, logout (route handlers), "session ended"
    r/[realm]/          the console, one folder per tab (page.tsx, loading.tsx, Server Actions in actions.ts)
  components/ui/        design-system components (shadcn/ui style, OMSSO tokens)
  components/console/   header, tabs, drawers, step-up, confirmations, progress bar, skeletons
  lib/                  env, session cookie, OIDC, Admin API client, types, form helpers, page titles
tests/                  Vitest
e2e/                    Playwright + run.sh (the stack for the tests)
```

## Loading states

Every click shows something at once, whatever the network:

- **progress bar** at the top and **dimmed content** while a page, a filter or a search loads
  (`components/console/navigation-progress.tsx`; links use `NavLink`, forms `SearchForm`). The bar
  is drawn by a **Web Worker** on an `OffscreenCanvas` (`progress-bar.ts`, `progress-worker.ts`):
  its animation runs on its own thread and keeps moving while the page's main thread is busy.
  Browsers without `OffscreenCanvas` in workers get the CSS bar instead;
- **skeleton** of each page (`loading.tsx`: real title and column headers, grey rows); a new filter
  or page of results reloads only the table (`<Suspense key=…>` around it);
- **drawers** (640 px, 760 px for clients) open and close at the click, with a skeleton until the
  item arrives (`components/console/drawer.tsx`);
- **spinner** in the button of a running action (`<Button loading>`).

`npm run dev` is slower than the real thing: it compiles each page the first time it is opened, and
**prefetching only runs in production** (with `npm run build && npm start`, the tabs' skeletons are
loaded in the background and a click shows the next page at once).

## Security notes

- Session cookie: JWE (`dir` + `A256GCM`), key derived from `SESSION_SECRET` with HKDF, `HttpOnly`,
  `SameSite=Lax`, `__Host-` prefix and `Secure` over HTTPS, 12 hours at most.
- Every change needs a second factor verified in the last minutes (step-up): the console offers
  "Confirm it's you" (new sign-in with `prompt=login`) before editing; the Admin API checks again.
- Refresh tokens rotate and a reused one revokes the whole family: the console refreshes once per
  token (in-process). Run **one** console instance, or sticky sessions.
- Read cache (`src/lib/cache.ts`): `GET /me`, the realm list and the reference lists of the drawers
  (roles, groups, client scopes, permissions) are kept 30 s per session, in-process. Any successful
  change through the Admin API empties it; a page's main table is never cached. The Admin API still
  checks every permission itself: a stale menu can show a button, never grant the action.
- CSP with a per-request nonce, `frame-ancestors 'none'`, no third-party resource (fonts bundled).
