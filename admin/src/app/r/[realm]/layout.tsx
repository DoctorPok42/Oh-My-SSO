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
import { pageHref, readableNav } from "@/lib/nav";
import { can, stepUpFresh } from "@/lib/permissions";
import { parseTheme, THEME_COOKIE } from "@/lib/theme";
import type { List, Realm } from "@/lib/types";

// Every console page: /r/<realm>/<tab>. The realm being administered is in
// the URL (bookmarkable, two tabs on two realms work), the header and the
// menus come from here. The menus show what the admin may read (lib/nav.ts).

export default async function ConsoleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ realm: string }>;
}) {
  const { realm } = await params;
  // The bell loads its own items after the page is shown (header-actions.ts).
  const me = await getMe();
  if (!me.ok) {
    return (
      <main className="mx-auto max-w-[720px] px-6 py-16">
        <ErrorState error={me} />
      </main>
    );
  }
  // The list of realms needs realm:read. Without it the admin keeps the pages
  // they may read, with no realm switcher. It is not even asked for: each
  // refused call writes "authorization denied" in the audit log.
  const realms = can(me.data, "realm") ? await loadCached<List<Realm>>("/realms") : null;
  const realmList = realms?.ok ? realms.data.items : [];
  if (realms?.ok && !realmList.some((r) => r.name === realm)) notFound();

  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);
  const { tm } = await getI18n();
  const sections = readableNav(me.data).map((s) => ({
    id: s.id,
    label: tm(s.label),
    pages: s.pages.map((p) => ({
      slug: p.slug,
      tab: p.tab,
      icon: p.icon,
      label: tm(p.label),
      href: pageHref(realm, p),
    })),
  }));

  return (
    <StepUpProvider freshUntil={me.data.step_up_fresh_until} initialFresh={stepUpFresh(me.data)}>
      {/* The top bar (NextTopLoader, root layout) also shows for searches, drawers and reloads. */}
      <NavigationProgress />
      <DrawerNavProvider>
        <Header me={me.data} realms={realmList} realm={realm} theme={theme} canReadAudit={can(me.data, "audit_log")} />
        <NavTabs sections={sections} realm={realm} realmSystem={realmList.find((r) => r.name === realm)?.system} />
        <main className="mx-auto max-w-[1360px] px-4 py-8 sm:px-6">
          <PendingContent>{realms && !realms.ok ? <ErrorState error={realms} /> : children}</PendingContent>
        </main>
      </DrawerNavProvider>
    </StepUpProvider>
  );
}
