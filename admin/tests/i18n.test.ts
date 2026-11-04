import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { english, isMsg, m, translator } from "@/i18n";
import { languages, loadCatalog, matchLocale, messagesOf, validTag } from "@/i18n/catalog";

describe("i18n", () => {
  it("matches a tag to an available language, English by default", () => {
    expect(matchLocale("fr")).toBe("fr");
    expect(matchLocale("fr-CA")).toBe("fr");
    expect(matchLocale("FR_be")).toBe("fr");
    expect(matchLocale("en-GB")).toBe("en");
    expect(matchLocale("de")).toBeNull();
    expect(matchLocale("")).toBeNull();
    expect(matchLocale(undefined)).toBeNull();
    expect(languages()[0]).toEqual({ tag: "en", name: "English" });
    expect(languages().map((l) => l.tag)).toContain("fr");
  });

  it("uses the translation, else the English text of the code, with its values", () => {
    const fr = translator("fr", { "x.deleted": "{name} a été supprimé." });
    expect(fr.t("x.deleted", "{name} was deleted.", { name: "bob" })).toBe("bob a été supprimé.");
    expect(fr.t("x.missing", "Still {what}", { what: "English" })).toBe("Still English");
    expect(english.t("x.deleted", "{name} was deleted.", { name: "bob" })).toBe("bob was deleted.");
    expect(english.t("x.unknown", "{a} and {b}", { a: 1 })).toBe("1 and {b}");
  });

  it("picks the plural form of the language", () => {
    const fr = translator("fr", { "s.count.one": "{count} session", "s.count.other": "{count} sessions" });
    // French: 0 and 1 are singular; English: only 1.
    expect(fr.tn("s.count", 0, "{count} session", "{count} sessions")).toBe("0 session");
    expect(english.tn("s.count", 0, "{count} session", "{count} sessions")).toBe("0 sessions");
    expect(english.tn("s.count", 1, "{count} session", "{count} sessions")).toBe("1 session");
    expect(fr.tn("s.count", 2, "{count} session", "{count} sessions")).toBe("2 sessions");
  });

  it("translates a text declared earlier (m)", () => {
    const msg = m("pages.users.title", "Users & Roles");
    expect(isMsg(msg)).toBe(true);
    expect(isMsg("Users")).toBe(false);
    expect(english.tm(msg)).toBe("Users & Roles");
    expect(translator("fr", messagesOf("fr")).tm(msg)).not.toBe("Users & Roles");
  });

  it("has a name for each language, in that language", () => {
    expect(messagesOf("fr")["language.name"]).toBe("Français");
    expect(messagesOf("en")).toEqual({});
  });
});

describe("ADMIN_LOCALES_DIR", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  function dirWith(files: Record<string, string>): string {
    const d = mkdtempSync(join(tmpdir(), "omsso-locales-"));
    dirs.push(d);
    for (const [name, content] of Object.entries(files)) writeFileSync(join(d, name), content);
    return d;
  }

  it("adds a language and changes texts of a built-in one, without a rebuild", () => {
    const cat = loadCatalog(
      dirWith({
        "de.json": JSON.stringify({ "language.name": "Deutsch", "users.title": "Benutzer" }),
        "fr.json": JSON.stringify({ "users.title": "Comptes", "x.empty": "" }),
        "README.txt": "not a translation",
      }),
    );
    expect(matchLocale("de-AT", cat)).toBe("de");
    expect(languages(cat)).toEqual([
      { tag: "en", name: "English" },
      { tag: "de", name: "Deutsch" },
      { tag: "fr", name: "Français" },
    ]);
    expect(translator("de", messagesOf("de", cat)).t("users.title", "Users & Roles")).toBe("Benutzer");
    // A key missing from de.json shows in English.
    expect(translator("de", messagesOf("de", cat)).t("x.other", "Other")).toBe("Other");
    // fr.json changes one text, the other built-in ones stay; an empty text is ignored.
    expect(messagesOf("fr", cat)["users.title"]).toBe("Comptes");
    expect(messagesOf("fr", cat)["language.name"]).toBe("Français");
    expect("x.empty" in messagesOf("fr", cat)).toBe(false);
    // The built-in catalogue is not changed.
    expect(messagesOf("fr")["users.title"]).not.toBe("Comptes");
  });

  it("accepts a byte-order mark and a tag in any case (pt_BR.json)", () => {
    const cat = loadCatalog(dirWith({ "pt_BR.json": "\uFEFF" + JSON.stringify({ "language.name": "Português" }) }));
    expect(matchLocale("pt-BR", cat)).toBe("pt-br");
  });

  it("refuses a wrong file, with the file and the reason", () => {
    expect(() => loadCatalog(dirWith({ "deutsch-de.json": "{}" }))).toThrow(/deutsch-de\.json: the file name/);
    expect(() => loadCatalog(dirWith({ "de.json": "{ not json" }))).toThrow(/de\.json/);
    expect(() => loadCatalog(dirWith({ "de.json": "[]" }))).toThrow(/a JSON object of texts/);
    expect(() => loadCatalog(dirWith({ "de.json": '{"users.title": 3}' }))).toThrow(
      /"users.title": a text must be a string/,
    );
    const missing = join(tmpdir(), "omsso-locales-missing-dir");
    expect(() => loadCatalog(missing)).toThrow(/ADMIN_LOCALES_DIR .*omsso-locales-missing-dir/);
  });

  it("uses the IdP's rule for language tags", () => {
    for (const ok of ["fr", "de", "pt-br", "zh-hant-tw", "es-419"]) expect(validTag(ok)).toBe(true);
    for (const bad of ["", "f", "deutsch", "fr-", "fr_ca", "fr.ca", "fr-abcdefghi"]) expect(validTag(bad)).toBe(false);
  });
});
