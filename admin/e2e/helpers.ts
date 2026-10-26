import fs from "node:fs";
import path from "node:path";
import { expect, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";

// Shared by the global setup and the tests.

export const STATE_DIR = path.join(import.meta.dirname, ".state");
export const STORAGE = path.join(STATE_DIR, "admin.json");
const ACCOUNT = path.join(STATE_DIR, "account.json");

export type Account = { email: string; password: string; totpSecret: string; idp: string };

export function saveAccount(a: Account) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNT, JSON.stringify(a, null, 2));
}

export function account(): Account {
  return JSON.parse(fs.readFileSync(ACCOUNT, "utf8")) as Account;
}

/**
 * A fresh TOTP code. The IdP refuses a code twice (replay protection), so
 * when the current one was already used, wait for the next 30 s period.
 */
export async function totpCode(secret: string): Promise<string> {
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 });
  const last = path.join(STATE_DIR, "totp-last.txt");
  const used = fs.existsSync(last) ? fs.readFileSync(last, "utf8") : "";
  let code = totp.generate();
  while (code === used) {
    await new Promise((r) => setTimeout(r, 1000));
    code = totp.generate();
  }
  fs.writeFileSync(last, code);
  return code;
}

/** Signs in on the IdP's page (password, then the authenticator code), back to the console. */
export async function signInOnIdP(page: Page, a: Account, consoleURL: string) {
  await page.waitForURL((u) => u.href.startsWith(a.idp));
  const identifier = page.locator("#identifier");
  const code = page.locator("#code");
  await expect(identifier.or(code).first()).toBeVisible();
  if (await identifier.isVisible()) {
    await identifier.fill(a.email);
    await page.locator("#password").fill(a.password);
    await page.locator("#password-form button[type=submit]").click();
  }
  await expect(code).toBeVisible();
  await code.fill(await totpCode(a.totpSecret));
  await page.locator("#code-form button[type=submit]").click();
  await page.waitForURL((u) => u.href.startsWith(consoleURL));
}

/** The DS "Confirm it's you" dialog, if changes are locked: full step-up round trip. */
export async function stepUpIfAsked(page: Page, consoleURL: string) {
  const dialog = page.getByRole("dialog", { name: "Confirm it's you" });
  if (await dialog.isVisible().catch(() => false)) {
    await dialog.getByRole("link", { name: "Continue" }).click();
    await signInOnIdP(page, account(), consoleURL);
  }
}
