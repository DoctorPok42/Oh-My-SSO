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
    r/[realm]/          the console, one folder per tab (page.tsx, Server Actions in actions.ts)
  components/ui/        design-system components (shadcn/ui style, OMSSO tokens)
  components/console/   header, tabs, drawers, step-up, confirmations, progress bar, skeletons
  lib/                  env, session cookie, OIDC, Admin API client, types, form helpers, page titles
tests/                  Vitest
e2e/                    Playwright + run.sh (the stack for the tests)
```

## Loading states

A page the server answers quickly simply replaces the current one: nothing flashes in between. Every
click still shows something at once, whatever the network:

- **progress bar** at the top: [nextjs-toploader](https://github.com/TheSGJ/nextjs-toploader),
  mounted once in `app/layout.tsx`. It starts on every link click and ends when Next.js shows the
  page; the console's other waits (a search, a drawer, the reload after a change) start it too
  (`components/console/navigation-progress.tsx`);
- **dimmed content** while a page, a filter or a search loads (links use `NavLink`, forms
  `SearchForm`);
- **menus** follow the click before the page arrives (`nav-tabs.tsx`);
- **skeleton** of the next page (`components/console/page-skeletons.tsx`: real title and column
  headers, grey rows), only when it takes more than 300 ms. A filter or a search stays on the page,
  dimmed;
- **drawers** (640 px, 760 px for clients) open and close at the click, with a skeleton until the
  item arrives (`components/console/drawer.tsx`);
- **spinner** in the button of a running action (`<Button loading>`).

No `loading.tsx` and no `<Suspense fallback={<Skeleton />}>` around a page's content: once React has
shown a Suspense fallback it holds back what replaces it for 300 ms, so a skeleton turns a 30 ms page
into a 330 ms one (see `navigation-progress.tsx`). A test keeps them out (`tests/navigation.test.ts`).

`npm run dev` is slower than the real thing: it compiles each page the first time it is opened (about
a second per page, once per start of the server). To judge the console's speed, use
`npm run build && npm start`.

## Importing users from a CSV file

Users > **Import CSV**. The file is checked first and nothing is written until
you confirm; then it runs on the server (`idp-admin`), so the page can close.
Reopen the drawer to follow it, or tick the box to get an e-mail at the end.

```csv
email,username,name,department,groups,roles
alice@example.com,alice,Alice Moreau,Sales,staff|sales,support
bob@example.com,,Bob Martin,,staff,
```

| Column            | Meaning                                               |
| ----------------- | ----------------------------------------------------- |
| `email`           | Required.                                             |
| `username`        | Default: the part of the e-mail before `@`.           |
| `groups`, `roles` | Names that exist in the realm, separated by `\|`.     |
| anything else     | A profile attribute (`family_name`, `department`...). |

- **UTF-8**, `,` or `;`, 1 MB and 1000 users at most, one import at a time per realm.
- **Passwords never come from a file.** A column whose name looks like a password
  or a secret (`password`, `pwd`, `mdp`, `secret`, `token`, `hash`...) is left out
  when the header is read: its values reach neither the profile, nor the report,
  nor the logs. The preview names the columns it ignored.
- **Creation only.** A line about an account that exists is refused, never merged.
  Importing the same file again is therefore safe: it finishes an interrupted import.
- **Activation.** With e-mails, each account gets its invitation. Without, the
  report offers the links as a file: they are made when you ask (the database only
  holds their hash), so each download replaces the previous links.
- Reports are kept 30 days. `ADMIN_PANEL_URL` on `idp-admin` gives the e-mail
  its link to the report.

## Bulk actions

Tick rows, then use the bar above the table: Users, Roles, Groups, Sessions,
Settings > Security > Locked accounts, Clients, Client scopes, Timeouts and
Audit Log (export only: the log never changes). A new table needs a
`BulkProvider` around it (`components/console/bulk.tsx`) and a `POST .../bulk`
in the Admin API. Signing keys, policies and permissions have none on purpose:
they are decided one at a time, or are not lists.

- **100 items at most per operation.** "Select the results" takes the first
  100 of the filter; "Continue with the next results" does the rest, each pass
  confirmed. Revoking every session of an IP or a client works this way:
  filter, select the results, revoke.
- **Items run one after the other.** An item that cannot change is skipped, the
  others go on: the answer is always 200 and lists what became of each item.
- **Your own account (master realm) and your own session are left out**, by the
  API as well as by the greyed-out checkbox.
- **One audit entry per bulk action**, `bulk.completed` (`bulk.interrupted` when
  the server stopped first): it lists each item, its outcome and the changes
  made (including the e-mails queued), instead of one entry per item. Only a
  failed e-mail still gets an entry of its own, with the same `operation_id`.
  `/audit?operation=<id>` shows them, and the summary links there.
- **The selection is kept in `sessionStorage`**, per table and filters: it
  survives the pagination and the round trip to the IdP of a step-up.
- **What the configuration manages is left out.** A role can still be
  duplicated (the copy is an ordinary role, without members); a role still
  assigned to someone is skipped when deleting, unlike the one-by-one delete
  where the admin sees the member count.

**Force password reset** signs the users out and sends a link by e-mail;
signing in with the password is refused until they choose a new one, which
cannot be the old one. It goes through the e-mail on purpose: whoever holds a
stolen password must not be able to replace it. Passkeys keep working (they are
not what leaked). The action needs e-mail to be configured.

## Security notes

- Session cookie: JWE (`dir` + `A256GCM`), key derived from `SESSION_SECRET` with HKDF, `HttpOnly`,
  `SameSite=Lax`, `__Host-` prefix and `Secure` over HTTPS, 12 hours at most.
- Every change needs a second factor verified in the last minutes (step-up): the console offers
  "Confirm it's you" (new sign-in with `prompt=login`) before editing; the Admin API checks again.
- Refresh tokens rotate and a reused one revokes the whole family: the console refreshes once per
  token (in-process). Run **one** console instance, or sticky sessions.
- Caches, both per session and emptied by a change made in the console:
  - the browser keeps a page it has shown for 30 s (`experimental.staleTimes`, `next.config.ts`);
    `router.refresh()` empties it;
  - the server (`src/lib/cache.ts`, in-process) keeps the Admin API's reads: 5 s for the dashboard,
    sessions and audit log, 10 s for users, 30 s for `GET /me`, the language and the realm list, 60 s
    for the rest. A change in a realm drops that realm, for every admin; a change in the master realm,
    or to a realm itself, drops everything. The item of a drawer is never cached.

  A change made elsewhere (sign-ins, account console, CLI, configuration file) shows when the entry
  expires. A session revoked at the IdP is noticed at the first read that is not cached. The Admin
  API still checks every permission and every change itself.

- CSP with a per-request nonce, `frame-ancestors 'none'`, no third-party resource (fonts bundled).
