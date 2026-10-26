import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import { DrawerNavProvider } from "@/components/console/drawer";
import { Header } from "@/components/console/header";
import { NavTabs } from "@/components/console/nav-tabs";
import { NavigationProgress, PendingContent } from "@/components/console/navigation-progress";
import { StepUpProvider } from "@/components/console/step-up";
import { ErrorState } from "@/components/console/error-state";
import { getMe, loadCached } from "@/lib/api";
import { can, stepUpFresh } from "@/lib/permissions";
import { parseTheme, THEME_COOKIE } from "@/lib/theme";
import type { List, Realm } from "@/lib/types";

// Every console page: /r/<realm>/<tab>. The realm being administered is in
// the URL (bookmarkable, two tabs on two realms work), the header and the
// tabs come from here. Each tab is shown only with its "read" permission.

const TABS = [
  { slug: "dashboard", label: "Dashboard", resource: "realm" },
  { slug: "clients", label: "Clients", resource: "client" },
  { slug: "client-scopes", label: "Client Scopes", resource: "client_scope" },
  { slug: "sessions", label: "Sessions", resource: "session" },
  { slug: "audit", label: "Audit Log", resource: "audit_log" },
  { slug: "users", label: "Users & Roles", resource: "user" },
  { slug: "signing-keys", label: "Signing Keys", resource: "signing_key" },
  { slug: "mfa", label: "MFA Policies", resource: "mfa_policy" },
  { slug: "timeouts", label: "Timeouts", resource: "timeout" },
  { slug: "settings", label: "Settings", resource: "settings" },
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
  const tabs = TABS.filter((t) => can(me.data, t.resource));

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
