"use client";

import { createContext, useContext, useMemo } from "react";
import { english, translator, type Messages, type Translator } from "@/i18n";

// The language of the page for Client Components: the root layout passes
// the texts of the request's language (getI18n), once per page load.

const I18nContext = createContext<Translator>(english);

export function I18nProvider({
  locale,
  messages,
  children,
}: {
  locale: string;
  messages: Messages;
  children: React.ReactNode;
}) {
  const value = useMemo(() => translator(locale, messages), [locale, messages]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

/** t, tn, tm and the locale, in a Client Component. */
export function useT(): Translator {
  return useContext(I18nContext);
}
