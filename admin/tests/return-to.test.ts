import { describe, expect, it } from "vitest";
import { safeReturnTo } from "@/lib/return-to";

describe("safeReturnTo (no open redirect)", () => {
  it.each([
    ["/r/demo/clients?protocol=oidc", "/r/demo/clients?protocol=oidc"],
    ["/r/demo/users#top", "/r/demo/users#top"],
    ["/", "/"],
  ])("keeps the local path %s", (input, want) => {
    expect(safeReturnTo(input)).toBe(want);
  });

  it.each([
    "https://evil.example/",
    "//evil.example/path",
    "/\\evil.example",
    "javascript:alert(1)",
    "r/demo",
    "/auth/login?returnTo=/x",
    "/auth/callback",
    "/r/demo\n/x",
    "",
    null,
    undefined,
    "/" + "a".repeat(3000),
  ])("refuses %s", (input) => {
    expect(safeReturnTo(input as string, "/fallback")).toBe("/fallback");
  });

  it("normalises dot segments", () => {
    expect(safeReturnTo("/r/demo/../../auth/login")).toBe("/");
    expect(safeReturnTo("/r/demo/./users")).toBe("/r/demo/users");
  });
});
