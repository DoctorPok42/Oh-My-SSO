import type { Metadata, Viewport } from "next";
import { cookies, headers } from "next/headers";
import NextTopLoader from "nextjs-toploader";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { I18nProvider } from "@/i18n/client";
import { getI18n } from "@/i18n/server";
import { parseTheme, THEME_COOKIE, themeClass } from "@/lib/theme";

// Fonts are bundled (@fontsource): no request to Google Fonts, nothing to
// allow in the CSP, nothing leaked about who opens the console.

export async function generateMetadata(): Promise<Metadata> {
  const { t } = await getI18n();
  return {
    title: { default: t("app.title", "OMSSO Admin"), template: t("app.title_template", "%s · OMSSO Admin") },
    description: t("app.description", "Oh-My-SSO administration console"),
    robots: { index: false, follow: false },
    referrer: "same-origin",
  };
}

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);
  // The page's CSP nonce (proxy.ts), for the bar's <style> element.
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  // The admin's language (src/i18n): its texts go to the Client Components once.
  const { locale, messages } = await getI18n();
  return (
    <html lang={locale} className={themeClass(theme)} suppressHydrationWarning>
      <body className="min-h-dvh">
        {/* The thin bar at the top while the next page loads: starts on every
            link click, ends when Next.js shows the page. The console's other
            waits (search, drawers, reload after a change) start it too:
            components/console/navigation-progress.tsx. */}
        <NextTopLoader color="var(--accent)" height={3} showSpinner={false} shadow={false} zIndex={100} nonce={nonce} />
        <I18nProvider locale={locale} messages={messages}>
          {children}
          <Toaster />
        </I18nProvider>
      </body>
    </html>
  );
}
