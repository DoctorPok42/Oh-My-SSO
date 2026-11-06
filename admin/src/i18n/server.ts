import "server-only";
import { cookies } from "next/headers";
import { cache } from "react";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { cached } from "@/lib/cache";
import type { Session } from "@/lib/session";
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
 * Every call to the Admin API waits for the language (its error sentences
 * are in it), so GET /me/language goes through the 30-second read cache
 * (lib/cache.ts). A language changed in Settings shows on the next page (a
 * change empties the cache), one changed in the account console within 30
 * seconds (the claim alone would wait for a new ID token).
 */
export const getI18n = cache(async (): Promise<Translator & { messages: Messages }> => {
  const session = await getSession();
  const cookie = (await cookies()).get(LOCALE_COOKIE)?.value;
  const lang = session ? await meLanguage(session) : null;
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
async function meLanguage(session: Session): Promise<MeLanguage | null> {
  const res = await cached(`${session.user.sub}:${session.createdAt}:/me/language`, async () => {
    try {
      return { ok: true as const, data: await api<MeLanguage>("/me/language", { noI18n: true }) };
    } catch {
      return { ok: false as const };
    }
  });
  return res.ok ? res.data : null;
}
