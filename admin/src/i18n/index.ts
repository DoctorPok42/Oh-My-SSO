// The languages of the console, like the IdP's (internal/i18n).
//
// English is the language of the code: every text is written in English
// where it is used, next to a key that names it:
//
//   t("users.title", "Users & Roles")
//   t("users.deleted", "{name} was deleted.", { name })
//   tn("sessions.count", n, "{count} session", "{count} sessions")
//   m("pages.users.title", "Users & Roles")   a text for later (constants)
//
// So English needs no file, and a text missing from a translation shows in
// English. Every other language is one flat JSON file, key -> text, like the
// admin translations of Strapi (src/admin/translations/fr.json): built in
// (./translations) or added without a rebuild (ADMIN_LOCALES_DIR). They are
// read on the server only: catalog.ts. `npm run i18n:check` lists the
// missing and unused keys.
//
// The console's language: the admin's choice (account console), else this
// browser's (omsso_locale cookie, shared with the IdP's pages), else the
// default of the admin's realm, else English. See server.ts and docs/I18N.md.
//
// This module is shared with the browser: it holds no translation.

export type Messages = Record<string, string>;
export type Values = Record<string, string | number>;

export const ENGLISH = "en";

/** A text to translate later, when the language is known (constants of lib/). */
export type Msg = { key: string; def: string; values?: Values };

export function m(key: string, def: string, values?: Values): Msg {
  return { key, def, values };
}

export type Translator = {
  locale: string;
  /** The text of key, else def, with {placeholders} replaced. */
  t: (key: string, def: string, values?: Values) => string;
  /** A text that depends on a number: key.one / key.other; {count} is n. */
  tn: (key: string, n: number, one: string, other: string, values?: Values) => string;
  /** A Msg (m(...)), with more values if needed. */
  tm: (msg: Msg, values?: Values) => string;
};

function fill(s: string, values?: Values): string {
  if (!values || !s.includes("{")) return s;
  return s.replace(/\{([a-z_]+)\}/gi, (whole, name: string) => (name in values ? String(values[name]) : whole));
}

export function translator(locale: string, messages: Messages): Translator {
  const plural = new Intl.PluralRules(locale);
  const t: Translator["t"] = (key, def, values) => fill(messages[key] ?? def, values);
  return {
    locale,
    t,
    tn: (key, n, one, other, values) =>
      plural.select(n) === "one"
        ? t(`${key}.one`, one, { count: n, ...values })
        : t(`${key}.other`, other, { count: n, ...values }),
    tm: (msg, values) => t(msg.key, msg.def, { ...msg.values, ...values }),
  };
}

/** English, for code that runs without a language (tests, logs). */
export const english: Translator = translator(ENGLISH, {});

/** A Msg (m(...)), not a string or a React element. */
export function isMsg(v: unknown): v is Msg {
  return typeof v === "object" && v !== null && "key" in v && "def" in v && typeof (v as Msg).def === "string";
}
