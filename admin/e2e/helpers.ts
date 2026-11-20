import fs from "node:fs";
import path from "node:path";
import { expect, type CDPSession, type Page } from "@playwright/test";

// Shared by the global setup and the tests.

export const STATE_DIR = path.join(import.meta.dirname, ".state");
export const STORAGE = path.join(STATE_DIR, "admin.json");
const ACCOUNT = path.join(STATE_DIR, "account.json");

/** A passkey as Chromium's virtual authenticator exports it (CDP WebAuthn.Credential). */
export type Key = {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string;
  userHandle?: string;
  signCount: number;
};

export type Account = { email: string; password: string; key?: Key; idp: string };

export function saveAccount(a: Account) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNT, JSON.stringify(a, null, 2));
}

export function account(): Account {
  return JSON.parse(fs.readFileSync(ACCOUNT, "utf8")) as Account;
}

// The accounts of master need a passkey or a security key, never an
// authenticator app alone: Chromium's virtual authenticator plays the device
// and answers every prompt at once. It lives with its page, so each page
// gets its own, loaded with the account's key when there is one.
const authenticators = new WeakMap<Page, { cdp: CDPSession; id: string }>();

/** Puts a virtual authenticator in page (before the IdP asks for it), holding a's key if any. */
export async function loadKey(page: Page, a: Account) {
  if (authenticators.has(page)) return;
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  if (a.key) await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: a.key });
  authenticators.set(page, { cdp, id: authenticatorId });
}

/**
 * Keeps a's key as the authenticator of page holds it now: the IdP refuses a
 * signature counter that goes back (a cloned key), so the next page must
 * start from this one. The shared account is written back for later tests.
 */
export async function keepKey(page: Page, a: Account) {
  const auth = authenticators.get(page);
  if (!auth) return;
  const { credentials } = await auth.cdp.send("WebAuthn.getCredentials", { authenticatorId: auth.id });
  a.key = credentials[0];
  if (fs.existsSync(ACCOUNT) && account().email === a.email) saveAccount(a);
}

/** Signs in on the IdP's page (password, then the passkey), back to the console. */
export async function signInOnIdP(page: Page, a: Account, consoleURL: string) {
  await loadKey(page, a);
  await page.waitForURL((u) => u.href.startsWith(a.idp));
  const back = page.waitForURL((u) => u.href.startsWith(consoleURL));
  const identifier = page.locator("#identifier");
  const passkey = page.locator("#passkey-btn");
  // With a session already, there is no password form, only the passkey step.
  await Promise.race([back, identifier.waitFor().catch(() => undefined), passkey.waitFor().catch(() => undefined)]);
  if (!page.url().startsWith(consoleURL) && (await identifier.isVisible())) {
    await identifier.fill(a.email);
    await page.locator("#password").fill(a.password);
    await page.locator("#password-form button[type=submit]").click();
  }
  // The page opens the passkey prompt by itself, or waits for "Continue"
  // (a step-up, or a ticked "don't ask again"): click it when it is offered.
  await expect
    .poll(
      async () => {
        if (
          !page.url().startsWith(consoleURL) &&
          (await passkey.isVisible()) &&
          (await passkey.isEnabled()) &&
          (await passkey.innerText()).trim() === "Continue"
        ) {
          await passkey.click().catch(() => undefined);
        }
        return page.url().startsWith(consoleURL);
      },
      { intervals: [250], timeout: 10_000 },
    )
    .toBe(true);
  await back;
  await keepKey(page, a);
}

/** The DS "Confirm it's you" dialog, if changes are locked: full step-up round trip. */
export async function stepUpIfAsked(page: Page, consoleURL: string) {
  const dialog = page.getByRole("dialog", { name: "Confirm it's you" });
  if (await dialog.isVisible().catch(() => false)) {
    const a = account();
    await loadKey(page, a); // before the IdP's page opens its prompt
    await dialog.getByRole("link", { name: "Continue" }).click();
    await signInOnIdP(page, a, consoleURL);
  }
}

/** Adds a passkey from the account console of the IdP (its sign-in page first), as a fresh account of master must. */
export async function addPasskey(page: Page, a: Account) {
  await loadKey(page, a);
  await page.goto(`${a.idp}/r/master/account/security/passkey`);
  await page.locator("#identifier").fill(a.email);
  await page.locator("#password").fill(a.password);
  await page.locator("#password-submit").click();
  await page.locator("#passkey-name").fill("e2e");
  await page.locator("#passkey-add").click();
  await expect(page.locator("#codes li").first()).toBeVisible();
  await keepKey(page, a);
}
