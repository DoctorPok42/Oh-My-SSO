import { describe, expect, it } from "vitest";
import { activeNav, firstReadablePage, hrefView, NAV, pageHref, readableNav } from "@/lib/nav";

const ids = (permissions: string[]) => readableNav({ permissions }).map((s) => s.id);
const pagesOf = (permissions: string[], id: string) =>
  readableNav({ permissions })
    .find((s) => s.id === id)
    ?.pages.map((p) => p.tab ?? p.slug);

describe("hrefView", () => {
  it("reads the page and the sub-page of a console URL", () => {
    expect(hrefView("/r/demo/users?tab=roles&offset=20")).toEqual({
      path: "/r/demo/users",
      slug: "users",
      tab: "roles",
    });
    expect(hrefView("/r/demo/clients")).toEqual({ path: "/r/demo/clients", slug: "clients", tab: null });
  });
  it("has no page outside a realm", () => {
    expect(hrefView("/").slug).toBe("");
    expect(hrefView("/r/demo").slug).toBe("");
  });
});

describe("console menus", () => {
  it("follows the design's order", () => {
    expect(NAV.map((s) => s.id)).toEqual([
      "dashboard",
      "applications",
      "access",
      "audit",
      "users",
      "signing-keys",
      "mfa",
      "settings",
    ]);
  });

  it("shows nothing without a read permission", () => {
    expect(ids([])).toEqual([]);
    // Write permissions alone do not open a page.
    expect(ids(["client:write", "user:write", "session:revoke"])).toEqual([]);
  });

  it("keeps a section for one readable page, with that page only", () => {
    expect(pagesOf(["client_scope:read"], "applications")).toEqual(["client-scopes"]);
    expect(pagesOf(["timeout:read"], "access")).toEqual(["timeouts"]);
    expect(ids(["client_scope:read"])).toEqual(["applications"]);
  });

  it("splits Users & Roles between the user and access permissions", () => {
    expect(pagesOf(["user:read"], "users")).toEqual(["users"]);
    expect(pagesOf(["access:read"], "users")).toEqual(["roles", "groups", "permissions"]);
    expect(pagesOf(["user:read", "access:read"], "users")).toEqual(["users", "roles", "groups", "permissions"]);
  });

  it("gives every sub-menu page an icon, and none to the pages alone in their section", () => {
    for (const s of NAV) {
      const sub = s.pages.length > 1;
      for (const p of s.pages) expect(!!p.icon).toBe(sub);
    }
  });

  it("does not change the catalogue when filtering", () => {
    readableNav({ permissions: ["client:read"] });
    expect(NAV.find((s) => s.id === "applications")?.pages).toHaveLength(2);
  });
});

describe("firstReadablePage", () => {
  it("finds the first page of the console", () => {
    expect(firstReadablePage({ permissions: ["realm:read", "client:read"] })?.slug).toBe("dashboard");
    expect(firstReadablePage({ permissions: ["timeout:read"] })?.slug).toBe("timeouts");
    expect(firstReadablePage({ permissions: [] })).toBeUndefined();
  });

  it("stays in the section when asked", () => {
    expect(firstReadablePage({ permissions: ["access:read", "client:read"] }, "users")?.tab).toBe("roles");
    expect(firstReadablePage({ permissions: ["user:read"] }, "users")?.tab).toBeUndefined();
    expect(firstReadablePage({ permissions: ["client:read"] }, "users")).toBeUndefined();
  });
});

describe("pageHref", () => {
  it("builds the link of a page and of a tab", () => {
    expect(pageHref("demo", { slug: "clients" })).toBe("/r/demo/clients");
    expect(pageHref("demo", { slug: "users", tab: "roles" })).toBe("/r/demo/users?tab=roles");
    expect(pageHref("a b", { slug: "users" })).toBe("/r/a%20b/users");
  });
});

describe("activeNav", () => {
  const all = readableNav({ permissions: ["user:read", "access:read", "settings:read", "client:read"] });
  const active = (slug: string, tab: string | null = null) => {
    const { section, page } = activeNav(all, slug, tab);
    return [section?.id, page?.tab ?? page?.slug];
  };

  it("finds the section and the page", () => {
    expect(active("clients")).toEqual(["applications", "clients"]);
    expect(active("users")).toEqual(["users", "users"]);
    expect(active("users", "groups")).toEqual(["users", "groups"]);
    expect(active("settings", "email")).toEqual(["settings", "email"]);
  });

  it("shows the default tab for an unknown ?tab=", () => {
    expect(active("users", "nope")).toEqual(["users", "users"]);
    expect(active("settings", "constructor")).toEqual(["settings", "settings"]);
  });

  it("leaves the menus alone on a page outside them", () => {
    expect(active("realms")).toEqual([undefined, undefined]);
    expect(active("client-scopes")).toEqual([undefined, undefined]); // not readable here
  });
});
