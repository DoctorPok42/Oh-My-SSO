import type { Metadata, Viewport } from "next";
import { cookies } from "next/headers";
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
  return (
    <html lang="en" className={themeClass(theme)} suppressHydrationWarning>
      <body className="min-h-dvh">
        {children}
        <Toaster />
      </body>
    </html>
  );
}
