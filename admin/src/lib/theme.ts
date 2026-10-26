// Theme preference: "light", "dark" or "system" (follow the OS), kept in a
// plain cookie so the server renders the right class on <html> at once (no
// flash of the wrong theme).
export type Theme = "light" | "dark" | "system";
export const THEME_COOKIE = "omsso_theme";

export function parseTheme(v: string | undefined): Theme {
  return v === "light" || v === "dark" ? v : "system";
}

/** Class for <html>: none for "system" (the tokens follow prefers-color-scheme). */
export function themeClass(t: Theme): string | undefined {
  return t === "system" ? undefined : t;
}

/** Remembers the choice for a year (browser side). */
export function saveTheme(t: Theme): void {
  document.cookie = `${THEME_COOKIE}=${t}; Path=/; Max-Age=31536000; SameSite=Lax`;
}
