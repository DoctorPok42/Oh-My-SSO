// Checks the translation files of the console (src/i18n/translations/*.json)
// against the code, like internal/i18n/keys_test.go does for the IdP:
//
//   - a key has one English text everywhere it is used;
//   - every file has every key, and only keys the code still uses;
//   - a translation has the same {placeholders} as its English text.
//
// The texts are found by reading the code: t("key", "English"),
// tn("key", n, "one", "other") and m("key", "English"). The audit actions are
// translated by code (audit.action.<code>, audit.category.<name>): their
// English texts come from the catalogue of the IdP,
// ../internal/core/audit/actions.go.
//
//   node scripts/i18n-check.mjs                 check (exit code 1 on a problem)
//   node scripts/i18n-check.mjs --dump en.json  also write the English catalogue
//   node scripts/i18n-check.mjs --dir <path>    check the files of an
//       ADMIN_LOCALES_DIR instead (src/i18n/catalog.ts). A file named like a
//       built-in language (fr.json) only changes it: its missing keys come
//       from the built-in file, as when the console runs.
//   npm run i18n:check -- --dir <path>          the same, through npm

import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src");
const translations = join(src, "i18n", "translations");
const auditCatalog = join(root, "..", "internal", "core", "audit", "actions.go");

// A string literal, in double or single quotes (Prettier picks single quotes
// when the text holds a double quote).
const str = String.raw`("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`;
const patterns = {
  text: new RegExp(String.raw`\b(?:t|m)\(\s*"([a-z0-9_.]+)",\s*` + str, "g"),
  plural: new RegExp(String.raw`\btn\(\s*"([a-z0-9_.]+)",\s*[^,]+,\s*` + str + String.raw`,\s*` + str, "g"),
};
const metaKeys = ["language.name"];

const problems = [];
const catalog = new Map(); // key -> { text, file }

function add(key, text, file) {
  const prev = catalog.get(key);
  if (prev && prev.text !== text) {
    problems.push(`${file}: key "${key}" has two English texts:\n  "${prev.text}" (${prev.file})\n  "${text}"`);
    return;
  }
  catalog.set(key, { text, file });
}

// The value of a literal: '...' becomes "..." (\' unescaped, " escaped).
const unquote = (lit) =>
  JSON.parse(lit.startsWith("'") ? `"${lit.slice(1, -1).replace(/\\'/g, "'").replace(/"/g, '\\"')}"` : lit);

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      walk(path);
      continue;
    }
    if (![".ts", ".tsx"].includes(extname(name))) continue;
    const code = readFileSync(path, "utf8");
    const file = path.slice(root.length + 1);
    for (const [, key, text] of code.matchAll(patterns.text)) add(key, unquote(text), file);
    for (const [, key, one, other] of code.matchAll(patterns.plural)) {
      add(`${key}.one`, unquote(one), file);
      add(`${key}.other`, unquote(other), file);
    }
  }
}
walk(src);

// The audit catalogue: {AuthLogin, "Authentication", "Signed in"} and
// AuthLogin = "auth.login".
if (existsSync(auditCatalog)) {
  const go = readFileSync(auditCatalog, "utf8");
  const codes = new Map([...go.matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*=\s*"([a-z_.]+)"/gm)].map(([, c, v]) => [c, v]));
  for (const [, constant, category, label] of go.matchAll(/\{\s*([A-Z][A-Za-z0-9]*),\s*"([^"]+)",\s*"([^"]+)"\s*\}/g)) {
    const code = codes.get(constant);
    if (!code) continue;
    add(`audit.action.${code}`, label, "internal/core/audit/actions.go");
    add(`audit.category.${category.toLowerCase().replaceAll(" ", "_")}`, category, "internal/core/audit/actions.go");
  }
} else {
  console.warn(`i18n: ${auditCatalog} not found, the audit actions are not checked`);
}

if (catalog.size < 200) problems.push(`only ${catalog.size} texts found: the patterns no longer match the code`);

const placeholders = (s) => [...new Set(s.match(/\{[a-z_]+\}/gi) ?? [])].sort().join(",");

const readJson = (path) => JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
const jsonFiles = (dir) => readdirSync(dir).filter((n) => n.endsWith(".json"));

// The files to check: the built-in ones, or those of --dir over them.
const files = []; // { name, msgs }
const dirAt = process.argv.indexOf("--dir");
if (dirAt > 0) {
  const dir = process.argv[dirAt + 1] ? resolve(process.argv[dirAt + 1]) : "";
  if (!dir || !existsSync(dir) || !statSync(dir).isDirectory()) {
    console.error(`i18n: --dir needs a directory of <tag>.json files (got "${process.argv[dirAt + 1] ?? ""}")`);
    process.exit(2);
  }
  const tagRule = /^[a-z0-9]{1,3}(-[a-z0-9]{1,8})*$/; // the IdP's rule (internal/i18n validTag)
  for (const name of jsonFiles(dir)) {
    const tag = name.slice(0, -".json".length).trim().toLowerCase().replaceAll("_", "-");
    const label = join(dir, name);
    if (tag.length < 2 || tag.length > 35 || !tagRule.test(tag)) {
      problems.push(`${label}: the file name must be a language tag (de.json, pt-br.json)`);
      continue;
    }
    let own;
    try {
      own = readJson(label);
    } catch (err) {
      problems.push(`${label}: ${err.message}`);
      continue;
    }
    if (typeof own !== "object" || own === null || Array.isArray(own)) {
      problems.push(`${label}: a JSON object of texts is expected`);
      continue;
    }
    const builtIn = existsSync(join(translations, `${tag}.json`)) ? readJson(join(translations, `${tag}.json`)) : {};
    const msgs = { ...builtIn };
    for (const [key, text] of Object.entries(own)) {
      if (typeof text !== "string") problems.push(`${label}: "${key}": a text must be a string`);
      else if (text !== "") msgs[key] = text; // an empty text is ignored, as at run time
    }
    files.push({ name: label, msgs });
  }
  if (!files.length && !problems.length) problems.push(`${dir}: no <tag>.json file`);
} else {
  for (const name of jsonFiles(translations)) files.push({ name, msgs: readJson(join(translations, name)) });
}

for (const { name, msgs } of files) {
  for (const [key, { text, file }] of [...catalog].sort(([a], [b]) => a.localeCompare(b))) {
    if (!(key in msgs)) problems.push(`${name}: missing "${key}" (English: "${text}", ${file})`);
  }
  for (const [key, value] of Object.entries(msgs)) {
    if (metaKeys.includes(key)) continue;
    const used = catalog.get(key);
    if (!used) {
      problems.push(`${name}: "${key}" is not used by the code any more`);
      continue;
    }
    if (placeholders(value) !== placeholders(used.text)) {
      problems.push(
        `${name}: "${key}" has the placeholders [${placeholders(value)}], the English text [${placeholders(used.text)}]`,
      );
    }
  }
}

const dump = process.argv.indexOf("--dump");
if (dump > 0 && process.argv[dump + 1]) {
  const en = Object.fromEntries([...catalog].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, v.text]));
  writeFileSync(process.argv[dump + 1], JSON.stringify(en, null, 2) + "\n");
}

// exitCode, not exit(): exit() can cut a long report written to a pipe.
if (problems.length) {
  console.error(problems.join("\n"));
  console.error(`\ni18n: ${problems.length} problem(s), ${catalog.size} texts`);
  process.exitCode = 1;
} else {
  console.log(
    `i18n: ${catalog.size} texts, every translation complete` +
      (dirAt > 0 ? ` (${files.map((f) => f.name).join(", ")})` : ""),
  );
}
