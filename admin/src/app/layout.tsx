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
import { parseTheme, THEME_COOKIE, themeClass } from "@/lib/theme";

// Fonts are bundled (@fontsource): no request to Google Fonts, nothing to
// allow in the CSP, nothing leaked about who opens the console.

export const metadata: Metadata = {
  title: { default: "OMSSO Admin", template: "%s · OMSSO Admin" },
  description: "Oh-My-SSO administration console",
  robots: { index: false, follow: false },
  referrer: "same-origin",
};

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);
  // The page's CSP nonce (proxy.ts), for the bar's <style> element.
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={themeClass(theme)} suppressHydrationWarning>
      <body className="min-h-dvh">
        {/* The thin bar at the top while the next page loads: starts on every
            link click, ends when Next.js shows the page. The console's other
            waits (search, drawers, reload after a change) start it too:
            components/console/navigation-progress.tsx. */}
        <NextTopLoader color="var(--accent)" height={3} showSpinner={false} shadow={false} zIndex={100} nonce={nonce} />
        {children}
        <Toaster />
      </body>
    </html>
  );
}
