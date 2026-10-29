import { expect, test, type Page } from "@playwright/test";
import { stepUpIfAsked } from "./helpers";

// of the tests is not a member) and the admin's own account (refused).
test.describe.configure({ mode: "serial" });

const PAGE = "/r/master/timeouts";

async function openNew(page: Page, baseURL: string) {
  await page.goto(PAGE);
  await page.getByRole("button", { name: "Suspend…" }).click();
  await stepUpIfAsked(page, baseURL);
  const drawer = page.getByRole("dialog", { name: "Suspend for a while" });
  await expect(drawer).toBeVisible();
  return drawer;
}

async function pick(page: Page, kind: "A user" | "A group", search: string, name: string) {
  const drawer = page.getByRole("dialog", { name: "Suspend for a while" });
  await drawer.getByRole("radio", { name: kind }).click();
  await drawer.getByPlaceholder(/Search a/).fill(search);
  await drawer
    .getByRole("list", { name: /Matching/ })
    .getByRole("button", { name: new RegExp(`^${name}`) })
    .click();
  await expect(drawer.getByRole("button", { name: "Change" })).toBeVisible();
}

test("suspend a group for an hour, change the end, lift it", async ({ page, baseURL }) => {
  const drawer = await openNew(page, baseURL!);
  await pick(page, "A group", "audit", "auditors");
  await drawer.getByRole("radio", { name: "1 hour" }).click();
  await expect(drawer.getByText(/No member of auditors can sign in or get a token until/)).toBeVisible();

  // The reason is required.
  await drawer.getByRole("button", { name: "Suspend now" }).click();
  await expect(drawer.getByRole("alert")).toContainText("A reason is required");

  await drawer.getByLabel("Reason").fill("E2E: quarterly access review");
  await drawer.getByRole("button", { name: "Suspend now" }).click();
  await expect(page.getByText(/Suspended/).first()).toBeVisible();
  await expect(drawer).toBeHidden();

  const row = page.getByRole("row", { name: /auditors/ });
  await expect(row.getByText("In force")).toBeVisible();
  await expect(row.getByText("E2E: quarterly access review")).toBeVisible();

  // No end any more.
  await row.getByRole("button", { name: "Edit" }).click();
  const edit = page.getByRole("dialog", { name: "Timeout of auditors" });
  await expect(edit).toBeVisible();
  await edit.getByRole("radio", { name: "No end" }).click();
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Timeout saved")).toBeVisible();
  await expect(edit.getByText("No end (until lifted)")).toBeVisible();
  await edit.getByRole("button", { name: "Cancel" }).click();
  await expect(row.getByText("No end")).toBeVisible();

  // Lift it.
  await row.getByRole("button", { name: "Lift" }).click();
  const confirm = page.getByRole("alertdialog", { name: /Lift the timeout of auditors/ });
  await confirm.getByRole("button", { name: "Lift timeout" }).click();
  await expect(page.getByText("Timeout lifted")).toBeVisible();
  await expect(page.getByText("Nobody is suspended, and nothing is scheduled.")).toBeVisible();

  await page.getByRole("link", { name: "Past" }).click();
  await expect(page.getByRole("row", { name: /auditors/ }).getByText("Lifted", { exact: true })).toBeVisible();
});

test("an administrator cannot suspend their own account", async ({ page, baseURL }) => {
  const drawer = await openNew(page, baseURL!);
  await pick(page, "A user", "e2e-admin", "e2e-admin");
  await drawer.getByLabel("Reason").fill("should be refused");
  await drawer.getByRole("button", { name: "Suspend now" }).click();
  await expect(drawer.getByText("you cannot suspend your own account")).toBeVisible();
  await drawer.getByRole("button", { name: "Cancel" }).click();
  await expect(drawer).toBeHidden();
});

test("schedule a timeout from the group's drawer, then cancel it", async ({ page, baseURL }) => {
  await page.goto("/r/master/users?tab=groups");
  await page
    .getByRole("row", { name: /auditors/ })
    .getByRole("button", { name: /Edit|View/ })
    .click();
  const group = page.getByRole("dialog", { name: "auditors" });
  await group.getByRole("link", { name: "Suspend…" }).click();
  await expect(page).toHaveURL(/\/r\/master\/timeouts\?new=1&target_type=group/);
  await stepUpIfAsked(page, baseURL!);

  const drawer = page.getByRole("dialog", { name: "Suspend for a while" });
  await expect(drawer.getByText("auditors", { exact: true })).toBeVisible(); // pre-filled
  await drawer.getByRole("radio", { name: "Later" }).click();
  const start = new Date(Date.now() + 2 * 86_400_000);
  const p = (n: number) => String(n).padStart(2, "0");
  const local = `${start.getFullYear()}-${p(start.getMonth() + 1)}-${p(start.getDate())}T09:00`;
  await drawer.getByLabel("Start date and time").fill(local);
  await drawer.getByRole("radio", { name: "24 hours" }).click();
  await drawer.getByLabel("Reason").fill("E2E: maintenance window");
  await drawer.getByRole("button", { name: "Schedule" }).click();
  await expect(page.getByText(/Timeout scheduled for/)).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${PAGE}$`)); // the pre-fill parameters are gone

  const row = page.getByRole("row", { name: /E2E: maintenance window/ });
  await expect(row.getByText("Scheduled")).toBeVisible();
  await row.getByRole("button", { name: "Cancel timeout" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Cancel timeout" }).click();
  await expect(page.getByText("Timeout cancelled")).toBeVisible();
  await expect(page.getByText("Nobody is suspended, and nothing is scheduled.")).toBeVisible();
});
