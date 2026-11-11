"use client";

import { PageHeader } from "@/components/console/page-header";
import {
  ActionSkeleton,
  CardSkeleton,
  FilterSkeleton,
  FormCardSkeleton,
  TableSkeleton,
} from "@/components/console/skeletons";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useT } from "@/i18n/client";
import { hrefView } from "@/lib/nav";
import { COLUMNS, PAGES } from "@/lib/pages";

// What the next page will look like: its real title and column headers, grey
// shapes for the rest. Shown by PendingContent (navigation-progress.tsx) when
// a page takes long to arrive, never before: see the note there on why these
// are not loading.tsx files.

export function PageSkeleton({ href }: { href: string }) {
  const { slug, tab } = hrefView(href);
  return <div aria-busy="true">{body(slug, tab)}</div>;
}

const ACCESS_PAGES = { roles: PAGES.roles, groups: PAGES.groups } as const;
const SETTINGS_PAGES = {
  security: PAGES.settingsSecurity,
  sessions: PAGES.settingsSessions,
  email: PAGES.settingsEmail,
  audit: PAGES.settingsAudit,
} as const;

function body(slug: string, tab: string | null) {
  switch (slug) {
    case "dashboard":
      return <DashboardSkeleton />;
    case "clients":
      return (
        <>
          <PageHeader {...PAGES.clients} actions={<ActionSkeleton />} />
          <FilterSkeleton className="w-60" />
          <TableSkeleton columns={COLUMNS.clients} />
        </>
      );
    case "client-scopes":
      return (
        <>
          <PageHeader {...PAGES.clientScopes} actions={<ActionSkeleton />} />
          <TableSkeleton columns={COLUMNS.clientScopes} />
        </>
      );
    case "sessions":
      return (
        <>
          <PageHeader {...PAGES.sessions} />
          <TableSkeleton columns={COLUMNS.sessions} rows={8} />
        </>
      );
    case "timeouts":
      return (
        <>
          <PageHeader {...PAGES.timeouts} />
          <TableSkeleton columns={COLUMNS.timeouts} rows={4} />
        </>
      );
    case "audit":
      return (
        <>
          <PageHeader {...PAGES.audit} />
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <FilterSkeleton className="mb-0 w-60" />
            <Skeleton className="h-9 w-full max-w-[640px]" />
          </div>
          <TableSkeleton columns={COLUMNS.audit} rows={10} />
        </>
      );
    case "users":
      if (tab === "roles" || tab === "groups")
        return (
          <>
            <PageHeader {...ACCESS_PAGES[tab]} actions={<ActionSkeleton />} />
            <TableSkeleton columns={COLUMNS.access} />
          </>
        );
      if (tab === "permissions")
        return (
          <>
            <PageHeader {...PAGES.permissions} actions={<ActionSkeleton />} />
            <TableSkeleton columns={COLUMNS.permissions} />
          </>
        );
      return (
        <>
          <PageHeader {...PAGES.users} actions={<ActionSkeleton />} />
          <FilterSkeleton className="w-[30rem] max-w-full" />
          <TableSkeleton columns={COLUMNS.users} rows={8} />
        </>
      );
    case "signing-keys":
      return (
        <>
          <PageHeader {...PAGES.signingKeys} actions={<ActionSkeleton />} />
          <div className="mb-4 grid gap-4 md:grid-cols-2">
            {Array.from({ length: 2 }, (_, i) => (
              <Card key={i} className="p-4">
                <Skeleton className="h-4 w-56" />
                <Skeleton className="mt-3 h-9 w-full" />
              </Card>
            ))}
          </div>
          <TableSkeleton columns={COLUMNS.signingKeys} rows={4} />
        </>
      );
    case "mfa":
      return <MfaSkeleton />;
    case "settings":
      return (
        <>
          <PageHeader
            {...(tab === "security" || tab === "sessions" || tab === "email" || tab === "audit"
              ? SETTINGS_PAGES[tab]
              : PAGES.settingsGeneral)}
          />
          <div className="space-y-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <CardSkeleton lines={3} />
              <FormCardSkeleton fields={1} />
              <CardSkeleton lines={5} className="lg:col-span-2" />
            </div>
            <Skeleton className="h-9 w-36" />
          </div>
        </>
      );
    case "realms":
      return (
        <>
          <PageHeader {...PAGES.realms} actions={<ActionSkeleton />} />
          <TableSkeleton columns={COLUMNS.realms} rows={3} />
        </>
      );
    default:
      return <GenericSkeleton />;
  }
}

function DashboardSkeleton() {
  const { tm } = useT();
  return (
    <>
      <div className="mb-6">
        <h1 className="text-[22px] font-semibold">{tm(PAGES.dashboard.title)}</h1>
        <Skeleton className="mt-2 h-4 w-72" />
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="rounded-xl border border-border bg-surface p-5 shadow-elevation">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="mt-3 h-7 w-16" />
          </div>
        ))}
      </div>
      <Card className="mt-4 py-4">
        <div className="flex flex-wrap items-center gap-6">
          <Skeleton className="h-4 w-24" />
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-5 w-32" />
          ))}
        </div>
      </Card>
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <CardSkeleton lines={6} className="lg:col-span-2" />
        <div className="space-y-4">
          <CardSkeleton lines={2} />
          <CardSkeleton lines={2} />
        </div>
      </div>
      <CardSkeleton lines={2} className="mt-4" />
    </>
  );
}

function MfaSkeleton() {
  const { t } = useT();
  return (
    <>
      <PageHeader {...PAGES.mfa} />
      <FormCardSkeleton fields={3} />
      <h2 className="mt-8 mb-3 text-[15px] font-semibold">{t("mfa.per_role", "Per role")}</h2>
      <TableSkeleton columns={COLUMNS.mfaRoles} rows={3} />
      <h2 className="mt-8 mb-3 text-[15px] font-semibold">{t("mfa.per_client", "Per client")}</h2>
      <TableSkeleton columns={COLUMNS.mfaClients} rows={3} />
    </>
  );
}

function GenericSkeleton() {
  const { t } = useT();
  return (
    <div aria-label={t("common.loading", "Loading")}>
      <Skeleton className="h-7 w-48" />
      <Skeleton className="mt-2 h-4 w-80" />
      <div className="mt-8 space-y-3 rounded-xl border border-border bg-surface p-4">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    </div>
  );
}
