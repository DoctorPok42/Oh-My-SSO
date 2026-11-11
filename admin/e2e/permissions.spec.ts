import { execSync } from "node:child_process";
import fs from "node:fs";
import { expect, test, type Browser, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { account, signInOnIdP, totpCode, type Account } from "./helpers";

// ONE-OFF CHECK (not delivered): an admin who may read only part of the
// console. The console's client is managed by config, so the group is allowed
// on it directly in the throw-away e2e database.

test.describe.configure({ mode: "serial" });

const GROUP = "e2e-limited";
const FORBIDDEN = "You don't have access to this";
const SHOTS = "admin/e2e/screenshots/permissions";
const EMAIL = "limited@example.test";

// The database of the run: the one e2e/run.sh was given (E2E_DATABASE_URL), read the same way.
const DB = (process.env.E2E_DATABASE_URL ?? "postgres://sso:sso@localhost:5432/sso_e2e").replace(
  /.*\/([^/?]+)(\?.*)?$/,
  "$1",
);

const sql = (q: string) => execSync(`docker exec -i postgres psql -U sso -d ${DB} -At`, { input: q, encoding: "utf8" });

let limited: Page;

async function signIn(browser: Browser, baseURL: string, a: Account) {
  const context = await browser.newContext({
    baseURL,
    viewport: { width: 1280, height: 800 },
    storageState: { cookies: [], origins: [] }, // not the config's shared session
  });
  const page = await context.newPage();
  await page.goto("/auth/login");
  await signInOnIdP(page, a, baseURL);
  return page;
}

async function activate(page: Page, activation: string, a: Account) {
  await page.goto(activation);
  await page.locator("#password").fill(a.password);
  await page.locator("#confirm").fill(a.password);
  await page.locator("#reset-form button[type=submit]").click();
  await expect(page.locator("#done")).toBeVisible();
  await page.goto(`${a.idp}/r/master/account/security/totp`);
  await page.locator("#identifier").fill(a.email);
  await page.locator("#password").fill(a.password);
  await page.locator("#password-submit").click();
  await page.locator("#totp-name").fill("e2e");
  await page.locator("#totp-start button[type=submit]").click();
  await expect(page.locator("#totp-secret")).not.toBeEmpty();
  a.totpSecret = (await page.locator("#totp-secret").innerText()).replace(/\s+/g, "");
  OTPAuth.Secret.fromBase32(a.totpSecret);
  await page.locator("#totp-code").fill(await totpCode(a.totpSecret));
  await page.locator("#totp-form button[type=submit]").click();
  await expect(page.locator("#codes li").first()).toBeVisible();
}

const sections = (page: Page) => page.getByRole("navigation", { name: "Sections", exact: true }).getByRole("link");
const subSections = (page: Page) =>
  page.getByRole("navigation", { name: "Sub-sections", exact: true }).getByRole("link");

test.beforeAll(async ({ browser, baseURL }) => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const admin = await signIn(browser, baseURL!, account());

  await admin.goto("/r/master/users?tab=groups");
  await admin.getByRole("button", { name: "New group" }).click();
  const group = admin.getByRole("dialog", { name: "New group" });
  await group.getByLabel("Name", { exact: true }).fill(GROUP);
  const permissions = group.getByRole("group", { name: "Permissions" });
  await permissions.getByRole("button", { name: "client_scope:read" }).click();
  await permissions.getByRole("button", { name: "access:read" }).click();
  await group.getByRole("button", { name: "Create group" }).click();
  await expect(admin.getByRole("cell", { name: GROUP })).toBeVisible();

  sql(`INSERT INTO client_groups (id, granted_at, client_app_id, group_id)
       SELECT gen_random_uuid()::text, now(), c.id, g.id FROM client_apps c, groups g
       WHERE c.client_id = 'sso-admin' AND g.name = '${GROUP}';`);

  await admin.goto("/r/master/users");
  await admin.getByRole("button", { name: "Invite user" }).click();
  const invite = admin.getByRole("dialog", { name: "Invite user" });
  await invite.getByLabel("Email", { exact: true }).fill(EMAIL);
  await invite.getByLabel("Display name").fill("Limited Admin");
  await invite.getByRole("group", { name: "Groups" }).getByRole("button", { name: GROUP }).click();
  const send = invite.getByRole("checkbox", { name: "E-mail the activation link" });
  if (await send.isChecked()) await send.click();
  await invite.getByRole("button", { name: "Send invitation" }).click();
  const link = admin.getByRole("dialog", { name: "Send this activation link" });
  const activation = await link.locator("code").innerText();
  await admin.context().close();

  const a: Account = {
    email: EMAIL,
    password: "e2e-Limited-Horse-Battery-Staple",
    totpSecret: "",
    idp: new URL(activation).origin,
  };
  const setup = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  await activate(await setup.newPage(), activation, a);
  await setup.close();
  limited = await signIn(browser, baseURL!, a);
});

test.afterAll(async () => {
  await limited?.context().close();
});

test("limited: the console opens on the first page they may read, not on the dashboard", async () => {
  await limited.goto("/r/master/dashboard").catch(() => undefined); // interrupted by the redirect under test
  await expect(limited).toHaveURL(/\/r\/master\/client-scopes$/);
  await expect(limited.getByRole("heading", { level: 1, name: "Client Scopes" })).toBeVisible();
  await expect(limited.getByRole("cell", { name: "No client scope yet." })).toBeVisible(); // the real, empty list
  await expect(limited.getByText(FORBIDDEN)).toHaveCount(0);
  await limited.screenshot({ path: `${SHOTS}/limited-scopes.png` });
});

test("limited: the menus show the sections they may read, each with those pages only", async () => {
  await limited.goto("/r/master/client-scopes");
  await expect(sections(limited)).toHaveText(["Applications", "Users & Roles"]);
  await expect(subSections(limited)).toHaveText(["Client Scopes"]); // Clients left out

  await sections(limited).filter({ hasText: "Users & Roles" }).click();
  await expect(limited).toHaveURL(/\/r\/master\/users\?tab=roles$/); // not /users: they may not read it
  await expect(subSections(limited)).toHaveText(["Roles", "Groups", "Permissions"]);
  await expect(limited.getByText(FORBIDDEN)).toHaveCount(0);
  await limited.screenshot({ path: `${SHOTS}/limited-roles.png` });
});

test("limited: the users page goes on to a sub-page they may read", async () => {
  await limited.goto("/r/master/users");
  await expect(limited).toHaveURL(/\/r\/master\/users\?tab=roles$/);
  await expect(limited.getByRole("heading", { level: 1, name: "Roles" })).toBeVisible();
});

test("limited: no realm switcher and no search of users without their permissions", async () => {
  await limited.goto("/r/master/client-scopes");
  await expect(limited.getByRole("button", { name: /Switch realm/ })).toHaveCount(0);
  await expect(limited.getByRole("searchbox")).toHaveCount(0);
});

test("limited: what the audit log holds for this account before any forbidden page", async () => {
  const rows = sql(`SELECT a.action, a.status, count(*) FROM audit_logs a JOIN users u ON u.id = a.user_id
                    WHERE u.email = '${EMAIL}' GROUP BY 1, 2 ORDER BY 1, 2;`);
  console.log(`AUDIT limited (before forbidden page):\n${rows}`);
  expect(rows).not.toMatch(/denied/i);
});

test("limited: a page they may not read says so", async () => {
  await limited.goto("/r/master/clients");
  await expect(limited.getByText(FORBIDDEN)).toBeVisible();
  await limited.goto("/r/master/settings");
  await expect(limited.getByText(FORBIDDEN)).toBeVisible();
});

test("screens of the double header, as a full admin", async ({ browser, baseURL }) => {
  const admin = await signIn(browser, baseURL!, account());
  for (const [name, path, heading] of [
    ["dashboard", "dashboard", "Dashboard"],
    ["clients", "clients", "Clients"],
    ["sessions", "sessions", "Sessions"],
    ["users", "users", "Users"],
    ["roles", "users?tab=roles", "Roles"],
    ["general", "settings", "General"],
    ["security", "settings?tab=security", "Security"],
    ["settings-sessions", "settings?tab=sessions", "Sessions"],
    ["email", "settings?tab=email", "Email"],
    ["settings-audit", "settings?tab=audit", "Audit"],
  ] as const) {
    await admin.goto(`/r/master/${path}`);
    await expect(admin.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await admin.waitForLoadState("networkidle");
    await admin.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: name !== "dashboard" });
  }
  await admin.setViewportSize({ width: 390, height: 780 });
  await admin.goto("/r/master/settings?tab=security");
  await expect(admin.getByRole("heading", { level: 1, name: "Security" })).toBeVisible();
  await admin.screenshot({ path: `${SHOTS}/mobile.png` });
  await admin.context().close();
});
