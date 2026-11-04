import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ENGLISH, type Messages } from "@/i18n";
import fr from "./translations/fr.json";

// The translations of the console, read on this server only: the browser
// gets the texts of its language from the root layout (I18nProvider).
//
//   built in            ./translations/<tag>.json, compiled in (BUILT_IN)
//   ADMIN_LOCALES_DIR   <dir>/<tag>.json, read once at start-up: adds
//                       languages, or changes texts of the built-in ones
//                       (en.json changes English), without a rebuild
//
// Same rules as the IdP's LOCALES_DIR (internal/i18n): a file name that is
// not a language tag, or a file that is not a JSON object of texts, stops
// the console at start-up (instrumentation.ts), better than a page in the
// wrong language later. Empty texts are ignored: the built-in or English
// text stays. A directory that cannot be read stops the console too.

/** tag -> key -> text. English has no entry unless en.json changes it. */
export type Catalog = Record<string, Messages>;

const BUILT_IN: Catalog = { fr };

/** "pt_BR" -> "pt-br", like the IdP (i18n.Normalize). */
export function normalizeTag(tag: string): string {
  return tag.trim().toLowerCase().replaceAll("_", "-");
}

/** A language tag, the IdP's rule: "fr", "pt-br", "zh-hant-tw". */
export function validTag(tag: string): boolean {
  if (tag.length < 2 || tag.length > 35) return false;
  return tag.split("-").every((part, i) => /^[a-z0-9]{1,8}$/.test(part) && (i > 0 || part.length <= 3));
}

/** The built-in translations, then those of dir over them. Throws on a wrong file. */
export function loadCatalog(dir?: string): Catalog {
  const cat: Catalog = {};
  for (const [tag, msgs] of Object.entries(BUILT_IN)) cat[tag] = { ...msgs };
  if (!dir) return cat;

  const root = resolve(dir);
  const fail = (where: string, why: string) => new Error(`ADMIN_LOCALES_DIR ${where}: ${why}`);
  let names: string[];
  try {
    names = readdirSync(root)
      .filter((n) => n.endsWith(".json"))
      .sort();
  } catch (err) {
    throw fail(root, (err as Error).message);
  }
  for (const name of names) {
    const file = join(root, name);
    const tag = normalizeTag(name.slice(0, -".json".length));
    if (!validTag(tag)) throw fail(file, "the file name must be a language tag (de.json, pt-br.json)");
    let msgs: unknown;
    try {
      msgs = JSON.parse(readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
    } catch (err) {
      throw fail(file, (err as Error).message);
    }
    if (typeof msgs !== "object" || msgs === null || Array.isArray(msgs))
      throw fail(file, 'a JSON object of texts is expected: { "key": "text" }');
    const into = (cat[tag] ??= {});
    for (const [key, text] of Object.entries(msgs)) {
      if (typeof text !== "string") throw fail(file, `"${key}": a text must be a string`);
      if (text !== "") into[key] = text;
    }
  }
  return cat;
}

let current: Catalog | undefined;

/** The console's translations: loaded once, from ADMIN_LOCALES_DIR when it is set. */
export function catalog(): Catalog {
  return (current ??= loadCatalog(process.env.ADMIN_LOCALES_DIR));
}

/**
 * Loads the translations when the server starts (instrumentation.ts): a
 * wrong file stops it, with the reason, instead of failing every page.
 */
export function checkAtStartup(): void {
  try {
    const cat = catalog();
    const dir = process.env.ADMIN_LOCALES_DIR;
    if (dir) console.log(`translations: ADMIN_LOCALES_DIR ${resolve(dir)} (${Object.keys(cat).sort().join(", ")})`);
  } catch (err) {
    console.error(`Invalid admin console translations (see docs/I18N.md): ${(err as Error).message}`);
    process.exit(1);
  }
}

/** The available language for a tag ("fr-CA" -> "fr"), null when there is none. */
export function matchLocale(tag: string | null | undefined, cat: Catalog = catalog()): string | null {
  const t = normalizeTag(tag ?? "");
  if (!t) return null;
  const has = (x: string) => x === ENGLISH || x in cat;
  if (has(t)) return t;
  const base = t.split("-")[0] ?? "";
  return has(base) ? base : null;
}

/** The texts of a language ({} for English unless en.json changes it: the code has them). */
export function messagesOf(locale: string, cat: Catalog = catalog()): Messages {
  return cat[locale] ?? {};
}

/** The available languages, English first, each named in itself. */
export function languages(cat: Catalog = catalog()): { tag: string; name: string }[] {
  const others = Object.keys(cat)
    .filter((t) => t !== ENGLISH)
    .sort();
  return [
    { tag: ENGLISH, name: cat[ENGLISH]?.["language.name"] ?? "English" },
    ...others.map((tag) => ({ tag, name: cat[tag]?.["language.name"] ?? tag })),
  ];
}
