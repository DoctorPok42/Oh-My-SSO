import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import { DrawerNavProvider } from "@/components/console/drawer";
import { Header } from "@/components/console/header";
import { NavTabs } from "@/components/console/nav-tabs";
import { NavigationProgress, PendingContent } from "@/components/console/navigation-progress";
import { StepUpProvider } from "@/components/console/step-up";
import { ErrorState } from "@/components/console/error-state";
import { getI18n } from "@/i18n/server";
import { getMe, loadCached } from "@/lib/api";
import { PAGES } from "@/lib/pages";
import { can, stepUpFresh } from "@/lib/permissions";
import { parseTheme, THEME_COOKIE } from "@/lib/theme";
import type { List, Realm } from "@/lib/types";

// Every console page: /r/<realm>/<tab>. The realm being administered is in
// the URL (bookmarkable, two tabs on two realms work), the header and the
// tabs come from here. Each tab is shown only with its "read" permission.

const TABS = [
  { slug: "dashboard", label: PAGES.dashboard.title, resource: "realm" },
  { slug: "clients", label: PAGES.clients.title, resource: "client" },
  { slug: "client-scopes", label: PAGES.clientScopes.title, resource: "client_scope" },
  { slug: "sessions", label: PAGES.sessions.title, resource: "session" },
  { slug: "audit", label: PAGES.audit.title, resource: "audit_log" },
  { slug: "users", label: PAGES.users.title, resource: "user" },
  { slug: "signing-keys", label: PAGES.signingKeys.title, resource: "signing_key" },
  { slug: "mfa", label: PAGES.mfa.title, resource: "mfa_policy" },
  { slug: "timeouts", label: PAGES.timeouts.title, resource: "timeout" },
  { slug: "settings", label: PAGES.settings.title, resource: "settings" },
] as const;

export default async function ConsoleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ realm: string }>;
}) {
  const { realm } = await params;
  // In parallel: each call is a round trip to the Admin API. The bell loads
  // its own items after the page is shown (header-actions.ts).
  const [me, realms] = await Promise.all([getMe(), loadCached<List<Realm>>("/realms")]);
  if (!me.ok) {
    return (
      <main className="mx-auto max-w-[720px] px-6 py-16">
        <ErrorState error={me} />
      </main>
    );
  }
  const realmList = realms.ok ? realms.data.items : [];
  if (realms.ok && !realmList.some((r) => r.name === realm)) notFound();

  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);
  const { tm } = await getI18n();
  const tabs = TABS.filter((t) => can(me.data, t.resource)).map((t) => ({ slug: t.slug, label: tm(t.label) }));

  return (
    <StepUpProvider freshUntil={me.data.step_up_fresh_until} initialFresh={stepUpFresh(me.data)}>
      {/* The top bar (NextTopLoader, root layout) also shows for searches, drawers and reloads. */}
      <NavigationProgress />
      <DrawerNavProvider>
        <Header me={me.data} realms={realmList} realm={realm} theme={theme} canReadAudit={can(me.data, "audit_log")} />
        <NavTabs realm={realm} tabs={tabs} />
        <main className="mx-auto max-w-[1360px] px-4 py-8 sm:px-6">
          <PendingContent>{realms.ok ? children : <ErrorState error={realms} />}</PendingContent>
        </main>
      </DrawerNavProvider>
    </StepUpProvider>
  );
}
