import fs from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { account, signInOnIdP, stepUpIfAsked } from "./helpers";

// The main admin journeys, in order, on a realm created by the test.

test.describe.configure({ mode: "serial" });

const REALM = "e2e-corp";
const r = (path: string) => `/r/${REALM}/${path}`;

async function clickThenStepUp(page: Page, baseURL: string, name: string) {
  await page.getByRole("button", { name }).click();
  await stepUpIfAsked(page, baseURL);
}

test("dashboard of the master realm", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/r\/master\/dashboard$/);
  // In <main>: the whole page would also count the copy React streams in a
  // hidden <div id="S:…"> just before it shows it (strict mode: 2 elements).
  const main = page.getByRole("main");
  await expect(main.getByText("Active sessions")).toBeVisible();
  await expect(main.getByText("PostgreSQL")).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Sections" }).getByRole("link", { name: "Applications" }),
  ).toBeVisible();
});

test("the second menu groups the pages of a section", async ({ page }) => {
  await page.goto("/r/master/dashboard");
  const sections = page.getByRole("navigation", { name: "Sections", exact: true });
  const subSections = page.getByRole("navigation", { name: "Sub-sections", exact: true });
  await expect(subSections).toHaveCount(0); // the dashboard is a page on its own

  await sections.getByRole("link", { name: "Applications" }).click();
  await expect(page).toHaveURL(/\/r\/master\/clients$/);
  await expect(subSections.getByRole("link")).toHaveText(["Clients", "Client Scopes"]);
  await subSections.getByRole("link", { name: "Client Scopes" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Client Scopes" })).toBeVisible();
  await expect(sections.getByRole("link", { name: "Applications" })).toHaveAttribute("aria-current", "true");

  await sections.getByRole("link", { name: "Users & Roles" }).click();
  await subSections.getByRole("link", { name: "Roles" }).click();
  await expect(page).toHaveURL(/\/r\/master\/users\?tab=roles$/);
  await expect(page.getByRole("heading", { level: 1, name: "Roles" })).toBeVisible();
  await expect(subSections.getByRole("link", { name: "Roles" })).toHaveAttribute("aria-current", "page");
});

test("both menus stay in view while the page scrolls", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 500 });
  await page.goto("/r/master/settings?tab=email");
  const sections = page.getByRole("navigation", { name: "Sections", exact: true });
  const subSections = page.getByRole("navigation", { name: "Sub-sections", exact: true });
  const realm = sections.getByText("Realm: master");
  await expect(realm).toHaveCount(0); // the header still shows it
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await expect(realm).toBeVisible();
  await expect(sections).toBeInViewport();
  await expect(subSections).toBeInViewport();
  const [a, b] = [await sections.boundingBox(), await subSections.boundingBox()];
  expect(a!.y).toBeLessThanOrEqual(1); // stuck to the top: the header has scrolled away
  expect(b!.y).toBeGreaterThanOrEqual(a!.y + a!.height - 1); // the second right under the first
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect(realm).toHaveCount(0);
});

test("what was typed in the settings stays across their sub-pages", async ({ page }) => {
  await page.goto("/r/master/settings?tab=sessions");
  const subSections = page.getByRole("navigation", { name: "Sub-sections", exact: true });
  const idle = page.getByLabel("Idle timeout (minutes)");
  const before = await idle.inputValue();
  await idle.fill(String(Number(before) + 1));

  await subSections.getByRole("link", { name: "Email" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Email" })).toBeVisible();
  await expect(page.getByText("Unsaved changes")).toBeVisible();
  // The save bar floats: in reach at the bottom of the window, wherever the page is scrolled.
  const save = page.getByRole("button", { name: "Save changes" });
  await expect(save).toBeInViewport();
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect(save).toBeInViewport();

  await subSections.getByRole("link", { name: "Sessions" }).click();
  await expect(idle).toHaveValue(String(Number(before) + 1));
  // Back to the saved value: the bar slides away, and is gone once its exit animation ended.
  await idle.fill(before);
  await expect(page.getByRole("button", { name: "Save changes" })).toHaveCount(0);
});

test("the settings show the infrastructure's status", async ({ page }) => {
  await page.goto("/r/master/settings");
  const main = page.getByRole("main");
  await expect(main.getByRole("heading", { name: "Infrastructure status" })).toBeVisible();
  await expect(main.getByText("PostgreSQL")).toBeVisible();
});

test("the session cookie is out of reach of JavaScript", async ({ page, context }) => {
  await page.goto("/r/master/dashboard");
  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name.startsWith("omsso_admin."));
  expect(session).toMatchObject({ httpOnly: true, sameSite: "Lax", path: "/" });
  expect(await page.evaluate(() => document.cookie)).not.toContain("omsso_admin");
  // The tokens never appear in the page either.
  expect(await page.content()).not.toMatch(/eyJ[A-Za-z0-9_-]{20,}\./);
});

test("create a realm and switch to it", async ({ page, baseURL }) => {
  await page.goto("/r/master/realms");
  await clickThenStepUp(page, baseURL!, "New realm");
  const dialog = page.getByRole("dialog", { name: "New realm" });
  await dialog.getByLabel("Display name").fill("E2E Corp");
  await expect(dialog.getByLabel("Name", { exact: true })).toHaveValue(REALM);
  await dialog.getByRole("button", { name: "Create realm" }).click();
  await expect(page).toHaveURL(new RegExp(`${r("dashboard")}$`));
  await page.getByRole("button", { name: /Switch realm/ }).click();
  await expect(page.getByRole("menuitem", { name: /Administration/ })).toBeVisible();
  await page.keyboard.press("Escape");
});

test("create an OIDC client: the secret is shown once", async ({ page, baseURL }) => {
  await page.goto(r("clients"));
  await clickThenStepUp(page, baseURL!, "New client");
  await page.getByLabel("Name", { exact: true }).fill("Payroll");
  await page.getByLabel("Redirect URIs", { exact: true }).fill("https://payroll.example.com/callback");
  await page.getByRole("button", { name: "Create client" }).click();

  const secretDialog = page.getByRole("dialog", { name: "Payroll is ready" });
  await expect(secretDialog).toBeVisible();
  const secret = await secretDialog.locator("code").nth(1).innerText();
  expect(secret.length).toBeGreaterThanOrEqual(32);
  await secretDialog.getByRole("button", { name: "I've copied it" }).click();
  await expect(page.getByText(secret)).toHaveCount(0);

  // The drawer is now the client's: masked secret, regenerate gives a new one.
  await page.getByRole("button", { name: "Regenerate" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Regenerate secret" }).click();
  const again = page.getByRole("dialog", { name: "New client secret" });
  await expect(again).toBeVisible();
  expect(await again.locator("code").nth(1).innerText()).not.toBe(secret);
  await again.getByRole("button", { name: "I've copied it" }).click();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("cell", { name: "Payroll", exact: true })).toBeVisible();
});

test("create a client scope with a claim mapper", async ({ page, baseURL }) => {
  await page.goto(r("client-scopes"));
  await clickThenStepUp(page, baseURL!, "New client scope");
  await page.getByLabel("Name", { exact: true }).fill("payroll_profile");
  await page.getByRole("button", { name: "Add mapper" }).click();
  await page.getByLabel("User attribute").fill("profile.department");
  await page.getByLabel("Claim name").fill("department");
  await page.getByRole("button", { name: "Create scope" }).click();
  await expect(page.getByRole("cell", { name: "payroll_profile", exact: true })).toBeVisible();
});

test("invite a user without e-mail: the activation link is shown once", async ({ page, baseURL }) => {
  await page.goto(r("users"));
  await clickThenStepUp(page, baseURL!, "Invite user");
  await page.getByLabel("Email", { exact: true }).fill("alice@example.test");
  await page.getByLabel("Display name").fill("Alice Moreau");
  const send = page.getByRole("checkbox", { name: "E-mail the activation link" });
  if (await send.isChecked()) await send.click();
  await page.getByRole("button", { name: "Send invitation" }).click();
  const dialog = page.getByRole("dialog", { name: "Send this activation link" });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("code")).toContainText(`/r/${REALM}/auth/reset-password#token=`);
  await dialog.getByRole("button", { name: "I've copied it" }).click();
  await page.getByRole("button", { name: "Cancel" }).click();
  const row = page.getByRole("row", { name: /Alice Moreau/ });
  await expect(row.getByText("Invited")).toBeVisible();
});

test("import users from a CSV file: preview, background import, report", async ({ page, baseURL }) => {
  await page.goto(r("users"));
  await clickThenStepUp(page, baseURL!, "Import CSV");
  await page.getByLabel("CSV file").setInputFiles({
    name: "hires.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(
      "email,name,password\ncarol@example.test,Carol Durand,not-read\nalice@example.test,Duplicate,not-read\n",
    ),
  });

  // The preview: nothing written yet.
  await expect(page.getByText("Ignored columns, never read: password")).toBeVisible();
  await expect(page.getByRole("cell", { name: /already used/ })).toBeVisible();
  const send = page.getByRole("checkbox", { name: "E-mail each user their activation link" });
  if ((await send.count()) > 0 && (await send.isChecked())) await send.click();
  const notify = page.getByRole("checkbox", { name: "E-mail me when the import ends" });
  if ((await notify.count()) > 0) await notify.click();
  await page.getByRole("button", { name: "Import 1 user" }).click();

  // In the background, then the report.
  await expect(page.getByText("Import finished.")).toBeVisible();
  await expect(page.getByRole("cell", { name: /already used/ })).toBeVisible();

  // No e-mail: the links come as a file.
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download the activation links" }).click();
  const links = await download;
  expect(links.suggestedFilename()).toBe("activation-links.csv");

  await page.getByRole("dialog").getByRole("button", { name: "Close" }).first().click();
  const row = page.getByRole("row", { name: /Carol Durand/ });
  await expect(row.getByText("Invited")).toBeVisible();
});

test("bulk: suspend a selection, what cannot change is reported", async ({ page, baseURL }) => {
  await page.goto(r("users?q=example.test"));
  const select = (name: RegExp) => page.getByRole("row", { name }).getByRole("checkbox");
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });

  await select(/Alice Moreau/).check();
  await expect(bar.getByText("1 user selected")).toBeVisible();
  await bar.getByRole("button", { name: "Suspend" }).click();
  await stepUpIfAsked(page, baseURL!);
  await page.getByRole("alertdialog", { name: "Suspend 1 user?" }).getByRole("button", { name: "Suspend" }).click();
  const summary = page.getByTestId("bulk-result");
  await expect(summary.getByText("1 user updated")).toBeVisible();
  await expect(page.getByRole("row", { name: /Alice Moreau/ }).getByText("Suspended")).toBeVisible();

  // Selecting again and asking for the same thing: nothing to do, and it says so.
  await page.getByRole("checkbox", { name: "Select all on this page" }).check();
  await bar.getByRole("button", { name: "Suspend" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Suspend" }).click();
  await expect(summary.getByText(/1 already suspended/)).toBeVisible();

  // The result leads to the entries of the operation.
  await summary.getByRole("link", { name: /audit/ }).click();
  await expect(page).toHaveURL(/\/audit\?operation=op_/);
  await expect(page.getByRole("row", { name: /user\.updated|User updated/ }).first()).toBeVisible();
});

test("bulk: deleting asks for a word, and the selection survives the pages", async ({ page }) => {
  await page.goto(r("users?q=carol"));
  await page.getByRole("checkbox", { name: "Select all on this page" }).check();
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });
  await expect(bar).toBeVisible();
  await page.reload();
  await expect(bar).toBeVisible();

  await bar.getByRole("button", { name: "Delete" }).click();
  const dialog = page.getByRole("alertdialog");
  const confirm = dialog.getByRole("button", { name: "Delete" });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel(/to confirm/).fill("delete");
  await expect(confirm).toBeEnabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await bar.getByRole("button", { name: "Clear selection" }).click();
  await expect(bar).toBeHidden();
});

test("bulk: your own session and account are out of reach", async ({ page }) => {
  await page.goto("/r/master/sessions");
  const own = page.getByRole("checkbox", { name: "Your own session cannot be part of a bulk action" });
  await expect(own.first()).toBeDisabled();
  await page.goto("/r/master/users");
  await expect(page.getByRole("checkbox", { name: "Your own account cannot be part of a bulk action" })).toBeDisabled();
});

test("sessions can be filtered by IP address", async ({ page }) => {
  await page.goto("/r/master/sessions");
  await page.getByLabel("Filter by IP address").fill("203.0.113.1");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/ip=203\.0\.113\.1/);
  await expect(page.getByText("No active session.")).toBeVisible();
});

test("the locked accounts are listed with the security settings", async ({ page }) => {
  await page.goto(r("settings?tab=security"));
  await expect(page.getByText("No account is locked.")).toBeVisible();
});

test("bulk: the configuration of clients can be exported", async ({ page }) => {
  await page.goto(r("clients"));
  await page.getByRole("checkbox", { name: "Select all on this page" }).check();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export configuration" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe(`clients-${REALM}.json`);
  const body = JSON.stringify(JSON.parse(fs.readFileSync(await file.path(), "utf8")));
  expect(body).toContain("client_id");
  expect(body).not.toMatch(/"secret"/);
});

test("bulk: duplicate roles, a role in use is not deleted", async ({ page, baseURL }) => {
  await page.goto(r("users?tab=roles"));
  await clickThenStepUp(page, baseURL!, "New role");
  const drawer = page.getByRole("dialog", { name: "New role" });
  await drawer.getByLabel("Name").fill("auditor");
  await drawer.getByRole("button", { name: /Create|Save/ }).click();
  const row = page.getByRole("row", { name: /auditor/ });
  await expect(row).toBeVisible();

  await row.getByRole("checkbox").check();
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });
  await bar.getByRole("button", { name: "Duplicate" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Duplicate" }).click();
  await expect(page.getByTestId("bulk-result").getByText("1 role updated")).toBeVisible();
  await expect(page.getByRole("row", { name: /auditor-copy/ })).toBeVisible();
});

test("bulk: a pasted list adds members to a group", async ({ page, baseURL }) => {
  await page.goto(r("users?tab=groups"));
  await clickThenStepUp(page, baseURL!, "New group");
  const created = page.getByRole("dialog", { name: "New group" });
  await created.getByLabel("Name").fill("ops");
  await created.getByRole("button", { name: /Create|Save/ }).click();
  await page
    .getByRole("row", { name: /^Select ops/ })
    .getByRole("button", { name: "Edit" })
    .click();
  const drawer = page.getByRole("dialog");
  await drawer.getByLabel("Add members").fill("alice, carol\nnobody");
  await drawer.getByRole("button", { name: "Add 3 people" }).click();
  await expect(drawer.getByTestId("bulk-result").getByText("2 members added")).toBeVisible();
  await expect(drawer.getByTestId("bulk-result").getByText(/1 user not found/)).toBeVisible();
});

test("bulk: members are removed from a group on a selection", async ({ page, baseURL }) => {
  await page.goto(r("users?tab=groups"));
  await page
    .getByRole("row", { name: /^Select ops/ })
    .getByRole("button", { name: "Edit" })
    .click();
  const drawer = page.getByRole("dialog");
  await drawer.getByRole("row", { name: /alice/i }).getByRole("checkbox").check();
  const bar = drawer.getByRole("toolbar", { name: "Actions on the selection" });
  await expect(bar.getByText("1 member selected")).toBeVisible();
  await bar.getByRole("button", { name: "Remove from group" }).click();
  await stepUpIfAsked(page, baseURL!);
  await page
    .getByRole("alertdialog", { name: "Remove 1 member from this group?" })
    .getByRole("button", { name: "Remove from group" })
    .click();
  await expect(drawer.getByTestId("bulk-result").getByText("1 member removed")).toBeVisible();
  await expect(drawer.getByRole("row", { name: /alice/i })).toBeHidden();
  await expect(drawer.getByRole("row", { name: /carol/i })).toBeVisible();
});

test("bulk: the MFA policy of a selection of roles", async ({ page, baseURL }) => {
  await page.goto(r("mfa"));
  const row = page.getByRole("row", { name: /auditor-copy/ });
  await expect(row.getByText("Realm default")).toBeVisible();
  await row.getByRole("checkbox").check();
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });
  await bar.getByRole("button", { name: "Require MFA" }).click();
  await stepUpIfAsked(page, baseURL!);
  await page
    .getByRole("alertdialog", { name: "Require MFA for 1 role?" })
    .getByRole("button", { name: "Require MFA" })
    .click();
  await expect(page.getByTestId("bulk-result").getByText("1 role updated")).toBeVisible();
  await expect(row.getByText("Own rules")).toBeVisible();

  // Back to the realm default, from the "More" menu.
  await row.getByRole("checkbox").check();
  await bar.getByRole("button", { name: "More" }).click();
  await page.getByRole("menuitem", { name: "Back to realm default" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Back to realm default" }).click();
  await expect(row.getByText("Realm default")).toBeVisible();
});

test("bulk: the size of a selection is a setting of the realm", async ({ page, baseURL }) => {
  const setLimit = async (value: string) => {
    await page.goto(r("settings"));
    await page.getByLabel("Items per bulk action").fill(value);
    await clickThenStepUp(page, baseURL!, "Save changes");
    await expect(page.getByText("Settings saved")).toBeVisible();
  };
  await page.goto(r("settings"));
  await expect(page.getByLabel("Items per bulk action")).toHaveValue("100");
  await setLimit("1");

  await page.goto(r("users?q=example.test"));
  await page.getByRole("checkbox", { name: "Select all on this page" }).check();
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });
  await expect(bar.getByText("1 user selected")).toBeVisible();
  await bar.getByRole("button", { name: "Clear selection" }).click();

  await setLimit("100");
});

test("bulk: client scopes in use are out of the selection", async ({ page, baseURL }) => {
  await page.goto(r("client-scopes"));
  await page.getByRole("checkbox", { name: "Select all on this page" }).check();
  const bar = page.getByRole("toolbar", { name: "Actions on the selection" });
  await bar.getByRole("button", { name: "Delete" }).click();
  await stepUpIfAsked(page, baseURL!);
  const dialog = page.getByRole("alertdialog");
  await dialog.getByLabel(/to confirm/).fill("delete");
  await dialog.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByTestId("bulk-result")).toContainText("deleted");
});

test("bulk: the selected audit entries can be exported", async ({ page }) => {
  await page.goto(r("audit"));
  const rows = page.getByRole("checkbox", { name: /^Select (?!all)/ });
  await rows.first().check();
  await expect(page.getByText("Entry ID")).toBeHidden(); // ticking a row does not open it
  await rows.nth(1).check();
  await expect(page.getByText("2 entries selected")).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export as CSV" }).click();
  const file = await download;
  const lines = fs
    .readFileSync(await file.path(), "utf8")
    .trim()
    .split("\n");
  expect(lines).toHaveLength(3); // the header and the two entries
});

test("rotate the realm's JWT signing key", async ({ page, baseURL }) => {
  await page.goto(r("signing-keys"));
  await clickThenStepUp(page, baseURL!, "Rotate key");
  await page.getByRole("dialog", { name: "Rotate a signing key" }).getByRole("button", { name: "Rotate now" }).click();
  await expect(page.getByRole("cell", { name: "Rotating out" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "Active" }).first()).toBeVisible();
});

test("the audit log records every change", async ({ page }) => {
  await page.goto(r("audit"));
  for (const action of [
    "client.created",
    "client.secret_rotated",
    "user.invited",
    "realm.created",
    "signing_key.rotated",
  ]) {
    await page.goto(`${r("audit")}?action=${action}`);
    await expect(page.getByText(action, { exact: true }).first()).toBeVisible();
  }
  // Done by an administrator: the actor badge says so.
  await page.goto(`${r("audit")}?action=client.created&actor=admin`);
  await expect(page.getByRole("cell").getByText("Admin", { exact: true }).first()).toBeVisible();
});

test("the audit log exports the filtered entries", async ({ page }) => {
  await page.goto(`${r("audit")}?action=client.*`);
  await page.getByRole("button", { name: "Export" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("menuitem", { name: "CSV (spreadsheet)" }).first().click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^audit-.+\.csv$/);
});

test("disable and enable the realm", async ({ page }) => {
  await page.goto("/r/master/realms");
  const row = page.getByRole("row", { name: /E2E Corp/ });
  await row.getByRole("button", { name: "Disable" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Disable realm" }).click();
  await expect(row.getByText("Disabled")).toBeVisible();
  await row.getByRole("button", { name: "Enable" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Enable realm" }).click();
  await expect(row.getByText("Active")).toBeVisible();
});

test("the theme choice is remembered", async ({ page }) => {
  await page.goto("/r/master/dashboard");
  await page.getByRole("radio", { name: "Dark" }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator("html")).toHaveClass(/dark/);
  await page.getByRole("radio", { name: "System" }).click();
  await expect(page.locator("html")).not.toHaveClass(/dark/);
});

test("step-up: once the second factor is too old, changes ask for it again", async ({ page, baseURL }) => {
  test.setTimeout(360_000);
  // Shorten the window to 1 minute (the minimum), wait it out.
  await page.goto("/r/master/mfa");
  await page.getByLabel(/Step-up window/).fill("1");
  await page.getByRole("button", { name: "Save" }).first().click();
  await expect(page.getByText("Realm MFA policy saved")).toBeVisible();
  await page.waitForTimeout(80_000);

  // A bulk action asks too, and the selection comes back from the IdP.
  await page.goto(r("users?q=example.test"));
  await page
    .getByRole("row", { name: /Alice Moreau/ })
    .getByRole("checkbox")
    .check();
  await page.getByRole("button", { name: "Reactivate" }).click();
  const confirmIt = page.getByRole("dialog", { name: "Confirm it's you" });
  await confirmIt.getByRole("link", { name: "Continue" }).click();
  await expect(page.locator("#identifier")).toBeVisible();
  await signInOnIdP(page, account(), baseURL!);
  await page
    .getByRole("alertdialog", { name: "Reactivate 1 user?" })
    .getByRole("button", { name: "Reactivate" })
    .click();
  await expect(page.getByTestId("bulk-result").getByText("1 user updated")).toBeVisible();
  await expect(page).not.toHaveURL(/bulk=/);
  await page.waitForTimeout(80_000);

  await page.goto(r("clients"));
  await page.getByRole("button", { name: "New client" }).click();
  const dialog = page.getByRole("dialog", { name: "Confirm it's you" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("link", { name: "Continue" }).click();
  // prompt=login: password AND code again, even with a live IdP session.
  await expect(page.locator("#identifier")).toBeVisible();
  await signInOnIdP(page, account(), baseURL!);
  // Back where the admin was, with the drawer open (?new=1).
  await expect(page).toHaveURL(/\/clients\?new=1$/);
  await expect(page.getByRole("dialog", { name: "New client" })).toBeVisible();

  // Restore the default window.
  await page.goto("/r/master/mfa");
  await page.getByLabel(/Step-up window/).fill("10");
  await page.getByRole("button", { name: "Save" }).first().click();
  await expect(page.getByText("Realm MFA policy saved")).toBeVisible();
});

test("sign out ends the console and the IdP sessions", async ({ page, context }) => {
  await page.goto("/r/master/dashboard");
  await page.getByRole("button", { name: "Account menu" }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  expect((await context.cookies()).some((c) => c.name.startsWith("omsso_admin."))).toBe(false);
  // The IdP asks for the password again: its session ended too.
  await page.goto("/r/master/dashboard");
  await expect(page.locator("#identifier")).toBeVisible();
});
