import path from "node:path";
import { expect, test, type Page, type Route } from "@playwright/test";
import { account, signInOnIdP, STATE_DIR, STORAGE } from "./helpers";

// What the admin sees while something loads. The console's server answers
// too fast here to see anything, so the browser's requests for the next view
// are held for a moment (page.route): the loading states must show at once,
// then make way for the content.

const HOLD_MS = 1_500;

// The shared session may have been ended by "sign out" (console.spec.ts runs
// first): sign in again once if so, and use that session here.
const SESSION = path.join(STATE_DIR, "loading.json");
test.describe.configure({ mode: "serial" });
test.use({ storageState: SESSION });
test.beforeAll(async ({ browser, baseURL }) => {
  const context = await browser.newContext({ storageState: STORAGE, baseURL });
  const page = await context.newPage();
  await page.goto("/r/master/clients");
  // Signed out: the console sends to the IdP, or (session revoked while the
  // cookie remains) shows "Your session ended". Either way: sign in again.
  // (a real row's button: the table's skeleton has rows too)
  const signedIn = await page
    .getByRole("button", { name: /^(Edit|View)$/ })
    .first()
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

async function hold(route: Route) {
  // Prefetches (Next.js loads the next pages' skeletons in the background,
  // long before a click in real use) go through; only navigations wait.
  if (Object.keys(route.request().headers()).some((h) => h.includes("prefetch"))) {
    await route.continue().catch(() => undefined);
    return;
  }
  await new Promise((r) => setTimeout(r, HOLD_MS));
  await route.continue().catch(() => undefined); // the test may be over
}

/** Holds the console's requests (page data, not static files) whose URL matches. */
async function slowDown(page: Page, match: (url: URL) => boolean) {
  await page.route((url) => !url.pathname.startsWith("/_next/") && match(url), hold);
}

test("a drawer opens at the click, with a skeleton until its data arrives", async ({ page }) => {
  await page.goto("/r/master/clients");
  await slowDown(page, (url) => url.searchParams.has("edit"));
  await page
    .locator("tbody tr")
    .first()
    .getByRole("button", { name: /^(Edit|View)$/ })
    .click();

  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible({ timeout: 1_000 }); // long before HOLD_MS
  await expect(drawer.locator('[aria-busy="true"]')).toBeVisible();
  await expect(drawer.getByRole("heading", { name: "Admin console" })).toBeVisible({ timeout: 10_000 });
  await expect(drawer.locator('[aria-busy="true"]')).toHaveCount(0);

  // Closing does not wait for the server either.
  await slowDown(page, (url) => url.pathname.endsWith("/clients") && !url.searchParams.has("edit"));
  await drawer.getByRole("button", { name: "Cancel" }).click();
  await expect(drawer).toBeHidden({ timeout: 1_000 });
  await expect(page).not.toHaveURL(/edit=/, { timeout: 10_000 });
});

test("a filter keeps the page: progress bar, dimmed content, then the new table", async ({ page }) => {
  await page.goto("/r/master/clients");
  await slowDown(page, (url) => url.searchParams.get("protocol") === "oidc");
  await page.getByRole("link", { name: "OIDC", exact: true }).click();

  await expect(page.locator("#nprogress")).toBeAttached({ timeout: 1_000 });
  await expect(page.locator('[data-pending-content="true"]')).toBeAttached();
  await expect(page.getByRole("heading", { level: 1, name: "Clients" })).toBeVisible();

  await expect(page).toHaveURL(/protocol=oidc/, { timeout: 10_000 });
  await expect(page.locator("tbody tr").first()).toContainText("Admin console");
  await expect(page.locator("#nprogress")).toHaveCount(0);
  await expect(page.locator('[data-pending-content="true"]')).toHaveCount(0);
});

test("a search goes through the console (no full reload) and only the table waits", async ({ page }) => {
  await page.goto("/r/master/users");
  // A full page load would drop this marker.
  await page.evaluate(() => ((window as unknown as { __kept: boolean }).__kept = true));
  await slowDown(page, (url) => url.searchParams.has("q"));
  await page.locator("main").getByLabel("Search users").fill("e2e");
  await page.getByRole("button", { name: "Search", exact: true }).click();

  await expect(page.locator("#nprogress")).toBeAttached({ timeout: 1_000 });
  await expect(page).toHaveURL(/q=e2e/, { timeout: 10_000 });
  await expect(page.locator("tbody tr").first()).toContainText("e2e-admin");
  expect(await page.evaluate(() => (window as unknown as { __kept?: boolean }).__kept)).toBe(true);
});

test("every console page has a skeleton shaped like it", async ({ page }) => {
  await page.goto("/r/master/sessions");
  // In real use the tabs' skeletons were prefetched long before a click.
  // Clicked earlier, the current page stays (dimmed, with the progress bar)
  // until the server answers: tested by the filter test above.
  await page.waitForLoadState("networkidle");
  for (const [tab, heading] of [
    ["Dashboard", "Dashboard"],
    ["Clients", "Clients"],
    ["Audit Log", "Audit Log"],
    ["Settings", "Settings"],
  ] as const) {
    await slowDown(page, (url) => url.pathname.endsWith(`/${tab === "Audit Log" ? "audit" : tab.toLowerCase()}`));
    await page.getByRole("navigation", { name: "Sections" }).getByRole("link", { name: tab, exact: true }).click();
    // The title at once, and grey shapes where the content will be.
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible({ timeout: 1_000 });
    await expect(page.locator('main [aria-busy="true"]:not([data-pending-content])').first()).toBeVisible();
    // Then the real page.
    await expect(page.locator('main [aria-busy="true"]:not([data-pending-content])')).toHaveCount(0, {
      timeout: 10_000,
    });
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await page.waitForLoadState("networkidle");
  }
});
