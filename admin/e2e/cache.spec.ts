import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { account, signInOnIdP, STATE_DIR, stepUpIfAsked, STORAGE } from "./helpers";

// The route caches: going back to a page asks the server nothing, and a change
// shows at once. Admin console: next.config.ts, src/lib/cache.ts. Account
// console: account.js.

test.describe.configure({ mode: "serial" });

// The shared session may have been ended by another spec: sign in again if so.
const SESSION = path.join(STATE_DIR, "cache.json");
test.use({ storageState: SESSION });
test.beforeAll(async ({ browser, baseURL }) => {
  const context = await browser.newContext({ storageState: STORAGE, baseURL });
  const page = await context.newPage();
  await page.goto("/r/master/clients");
  const signedIn = await page
    .getByRole("heading", { level: 1, name: "Clients" })
    .waitFor({ timeout: 10_000 })
    .then(
      () => true,
      () => false,
    );
  if (!signedIn) {
    await page.goto("/auth/login?returnTo=%2Fr%2Fmaster%2Fdashboard");
    await signInOnIdP(page, account(), baseURL!);
  }
  await context.storageState({ path: SESSION });
  await context.close();
});

/** The console's requests for a page's data (not its prefetches). */
function pageRequests(page: Page) {
  const seen: string[] = [];
  page.on("request", (r) => {
    const h = r.headers();
    if (h["rsc"] && !h["next-router-prefetch"]) seen.push(r.url());
  });
  return seen;
}

test("admin console: a tab shown a moment ago comes back without asking the server", async ({ page }) => {
  await page.goto("/r/master/clients");
  const sections = page.getByRole("navigation", { name: "Sections" });
  await sections.getByRole("link", { name: "Audit Log", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Audit Log" })).toBeVisible();

  const requests = pageRequests(page);
  await sections.getByRole("link", { name: "Applications", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Clients" })).toBeVisible();
  expect(requests).toEqual([]);
});

test("admin console: a change shows at once on a page kept by the browser", async ({ page, baseURL }) => {
  const name = `cache-${Date.now()}`;
  await page.goto("/r/master/users?tab=groups");
  const sections = page.getByRole("navigation", { name: "Sections" });
  await sections.getByRole("link", { name: "Audit Log", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Audit Log" })).toBeVisible();
  await sections.getByRole("link", { name: "Users & Roles", exact: true }).click();
  await page
    .getByRole("navigation", { name: "Sub-sections", exact: true })
    .getByRole("link", { name: "Groups" })
    .click();
  await expect(page.getByRole("heading", { level: 1, name: "Groups" })).toBeVisible();

  await page.getByRole("button", { name: "New group" }).click();
  await stepUpIfAsked(page, baseURL!);
  await page
    .getByRole("button", { name: "New group" })
    .click({ timeout: 2_000 })
    .catch(() => undefined);
  const group = page.getByRole("dialog", { name: "New group" });
  await group.getByLabel("Name", { exact: true }).fill(name);
  await group.getByRole("button", { name: "Create group" }).click();
  await expect(page.getByRole("cell", { name })).toBeVisible();

  // The server's cache and the browser's both saw the change.
  await sections.getByRole("link", { name: "Audit Log", exact: true }).click();
  await expect(page.locator("tbody tr").filter({ hasText: /group/i }).first()).toBeVisible();
});

test("account console: a tab comes from memory, and a change empties it", async ({ browser, baseURL }) => {
  const a = account();
  const context = await browser.newContext({ baseURL, storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  const base = `${a.idp}/r/master/account`;
  await page.goto(base);
  await page.locator("#identifier").fill(a.email);
  await page.locator("#password").fill(a.password);
  await page.locator("#password-submit").click();
  const tabs = page.getByRole("navigation", { name: "Account sections" });
  const { totpCode } = await import("./helpers");
  const code = page.locator("#code");
  await expect(code.or(tabs).first()).toBeVisible();
  if (await code.isVisible()) {
    await code.fill(await totpCode(a.totpSecret));
    await page.locator("#code-form button[type=submit]").click();
  }
  await expect(tabs).toBeVisible();

  const fetched: string[] = [];
  page.on("request", (r) => {
    if (r.headers()["x-account-prefetch"]) fetched.push(new URL(r.url()).pathname);
  });
  // A full page load would drop this marker.
  await page.evaluate(() => ((window as unknown as { __kept: boolean }).__kept = true));

  const security = tabs.getByRole("link", { name: "Security" });
  await security.hover();
  await expect.poll(() => fetched.length).toBe(1);
  await security.click();
  await expect(page).toHaveURL(/\/account\/security$/);
  await expect(security).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
  expect(fetched).toEqual(["/r/master/account/security"]); // the hover's, no second one
  expect(await page.evaluate(() => (window as unknown as { __kept?: boolean }).__kept)).toBe(true);

  // Times and htmx work in what was swapped in.
  const sessions = tabs.getByRole("link", { name: "Sessions" });
  await sessions.click();
  await expect(page).toHaveURL(/\/account\/sessions$/);
  await expect(page.locator("#sessions time[data-local]").first()).toBeVisible();

  // Kept for the next visit, until a change: htmx saves the name, nothing stale stays.
  const profile = tabs.getByRole("link", { name: "Profile" });
  await profile.hover();
  await expect.poll(() => fetched.filter((f) => f.endsWith("/account")).length).toBe(1);
  await profile.click();
  await expect(page.locator("#main form").first()).toBeVisible();
  await security.hover();
  await security.click();
  await expect(page).toHaveURL(/\/account\/security$/);
  const before = fetched.length;
  await profile.click();
  await expect(page).toHaveURL(/\/account$/);
  await page.getByLabel("First name").fill("Cache");
  await page.getByRole("button", { name: "Save" }).first().click();
  await expect(page.locator("#profile-form").getByRole("status")).toHaveText("Saved");
  await security.hover();
  await expect.poll(() => fetched.length).toBeGreaterThan(before);

  // Back: the server shows the page again.
  await security.click();
  await expect(page).toHaveURL(/\/account\/security$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator("#main form").first()).toBeVisible();
  await context.close();
});
