import "server-only";
import { cookies } from "next/headers";
import { cache } from "react";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import type { MeLanguage } from "@/lib/types";
import { ENGLISH, translator, type Messages, type Translator } from "@/i18n";
import { matchLocale, messagesOf } from "@/i18n/catalog";

/** This browser's language, shared with the IdP's pages (internal/i18n). */
export const LOCALE_COOKIE = "omsso_locale";

/**
 * The language of this request, for Server Components, Server Actions and
 * Route Handlers, in the order of the IdP's pages (internal/httpserver/i18n.go):
 *
 *   the admin's choice      their account console (GET /me/language, else
 *                           the "locale" claim of their ID token)
 *   this browser's          the omsso_locale cookie
 *   the realm's default     Settings of the admin's realm (GET /me/language)
 *   English
 *
 * GET /me/language is asked on every request, never cached: a language
 * changed in the account console or in Settings shows on the next page (the
 * claim only changes with a new ID token). Once per request.
 */
export const getI18n = cache(async (): Promise<Translator & { messages: Messages }> => {
  const session = await getSession();
  const cookie = (await cookies()).get(LOCALE_COOKIE)?.value;
  const lang = session ? await meLanguage() : null;
  const locale =
    matchLocale(lang?.locale) ??
    matchLocale(session?.user.locale) ??
    matchLocale(cookie) ??
    matchLocale(lang?.realm_locale) ??
    ENGLISH;
  const messages = messagesOf(locale);
  return { ...translator(locale, messages), messages };
});

/** null when the Admin API cannot tell (the next steps decide). */
async function meLanguage(): Promise<MeLanguage | null> {
  try {
    return await api<MeLanguage>("/me/language", { noI18n: true });
  } catch {
    return null;
  }
}
