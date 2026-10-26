import { describe, expect, it } from "vitest";
import { formatPercent, formatRelative, initials, lines, pageLabel, secondsTo, toSeconds } from "@/lib/format";

describe("format helpers", () => {
  const now = new Date("2026-10-23T12:00:00Z");

  it("formats relative times", () => {
    expect(formatRelative("2026-10-23T11:59:50Z", now)).toBe("just now");
    expect(formatRelative("2026-10-23T11:55:00Z", now)).toBe("5 min ago");
    expect(formatRelative("2026-10-23T09:00:00Z", now)).toBe("3 h ago");
    expect(formatRelative("2026-10-25T12:00:00Z", now)).toBe("in 2 d");
    expect(formatRelative(null, now)).toBe("never");
    expect(formatRelative("0001-01-01T00:00:00Z", now)).toBe("never"); // Go's zero time
  });

  it("converts token lifetimes (0 = server default)", () => {
    expect(toSeconds("minutes", "15")).toBe(900);
    expect(toSeconds("days", "1,5")).toBe(129600);
    expect(toSeconds("minutes", "")).toBe(0);
    expect(toSeconds("minutes", "-3")).toBe(0);
    expect(secondsTo("minutes", 900)).toBe("15");
    expect(secondsTo("days", 0)).toBe("");
  });

  it("splits lines, builds labels", () => {
    expect(lines(" https://a/cb \n\n https://b/cb\r\n")).toEqual(["https://a/cb", "https://b/cb"]);
    expect(pageLabel(20, 20, 43)).toBe("21–40 of 43");
    expect(pageLabel(0, 0, 0)).toBe("0 of 0");
    expect(initials("Alice Moreau")).toBe("AM");
    expect(initials("root")).toBe("R");
    expect(formatPercent(100)).toBe("100%");
    expect(formatPercent(33.3)).toBe("33.3%");
    expect(formatPercent(1)).toBe("1%");
  });
});
