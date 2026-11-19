import fs from "node:fs";
import { chromium, expect, type FullConfig } from "@playwright/test";
import { addPasskey, saveAccount, signInOnIdP, STORAGE, type Account } from "./helpers";

// Once before the tests: the first administrator created by
// `idp-admin bootstrap` (e2e/run.sh) chooses a password with the activation
// link, adds a passkey in the account console of the IdP (/r/master/account),
// and signs in to the admin console. The browser state (session cookie) and
// the passkey are saved for the tests.
export default async function globalSetup(config: FullConfig) {
  const file = process.env.E2E_BOOTSTRAP_OUTPUT;
  if (!file) throw new Error("E2E_BOOTSTRAP_OUTPUT is not set: run the tests with e2e/run.sh (make admin-e2e)");
  const out = fs.readFileSync(file, "utf8");
  const activation = out.match(/https?:\/\/\S+\/auth\/reset-password#token=\S+/)?.[0];
  if (!activation) throw new Error(`no activation link in ${file}: was the database fresh?`);
  const idp = new URL(activation).origin;
  const consoleURL = config.projects[0]!.use.baseURL!;
  const a: Account = {
    email: process.env.E2E_ADMIN_EMAIL ?? "e2e-admin@example.test",
    password: "e2e-Correct-Horse-Battery-Staple",
    idp,
  };

  const browser = await chromium.launch(config.projects[0]!.use.launchOptions);
  const page = await browser.newPage();
  try {
    // 1. password, with the single-use activation link
    await page.goto(activation);
    await page.locator("#password").fill(a.password);
    await page.locator("#confirm").fill(a.password);
    await page.locator("#reset-form button[type=submit]").click();
    await expect(page.locator("#done")).toBeVisible();

    // 2. a passkey (master takes no authenticator app alone)
    await addPasskey(page, a);
    saveAccount(a);

    // 3. sign in to the console (a new browser: no IdP session yet)
    const context = await browser.newContext();
    const consolePage = await context.newPage();
    await consolePage.goto(`${consoleURL}/auth/login`);
    await signInOnIdP(consolePage, a, consoleURL);
    await expect(consolePage.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await context.storageState({ path: STORAGE });
  } finally {
    await browser.close();
  }
}
