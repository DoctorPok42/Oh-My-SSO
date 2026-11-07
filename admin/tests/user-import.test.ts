import { describe, expect, it } from "vitest";
import { csvCell, decodeCsvFile, IMPORT_TEMPLATE, importPercent, toCsv } from "@/lib/user-import";

describe("decodeCsvFile", () => {
  it("reads UTF-8, with or without a BOM", () => {
    expect(decodeCsvFile(new TextEncoder().encode("email,prénom\n").buffer)).toBe("email,prénom\n");
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, 0x65]);
    expect(decodeCsvFile(bom.buffer)).toBe("e");
  });

  it("refuses Latin-1 instead of turning its accents into �", () => {
    const latin1 = new Uint8Array([0x63, 0x61, 0x66, 0xe9]); // "café"
    expect(decodeCsvFile(latin1.buffer)).toBeNull();
  });
});

describe("csvCell", () => {
  it("quotes what needs it", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("two\nlines")).toBe('"two\nlines"');
    expect(csvCell(12)).toBe("12");
  });

  it("never gives a spreadsheet a formula from an uploaded file", () => {
    for (const bad of ["=1+1", "+33612345678", "-2", "@SUM(A1)", "\t=1", "\r=1"]) {
      const cell = csvCell(bad);
      expect(cell.replace(/^"/, "").startsWith("'")).toBe(true);
    }
    expect(csvCell('=HYPERLINK("http://evil.example","x")')).toBe(`"'=HYPERLINK(""http://evil.example"",""x"")"`);
  });
});

describe("toCsv", () => {
  it("is a file Excel reads as UTF-8", () => {
    expect(
      toCsv([
        ["line", "error"],
        [2, "déjà, utilisé"],
      ]),
    ).toBe('\uFEFFline,error\r\n2,"déjà, utilisé"\r\n');
  });
});

describe("importPercent", () => {
  it("stays within 0 and 100", () => {
    expect(importPercent({ processed: 0, total: 0 })).toBe(0);
    expect(importPercent({ processed: 1, total: 3 })).toBe(33);
    expect(importPercent({ processed: 3, total: 3 })).toBe(100);
    expect(importPercent({ processed: 4, total: 3 })).toBe(100);
  });
});

describe("IMPORT_TEMPLATE", () => {
  it("has no password column", () => {
    const header = IMPORT_TEMPLATE.split("\r\n")[0] ?? "";
    expect(header.split(",")).toContain("email");
    expect(header).not.toMatch(/pass|pwd/i);
  });
});
