import { NavLink } from "@/components/console/nav-link";
import { Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { apiPath, getMe, load } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { can, canWrite } from "@/lib/permissions";
import type { Dashboard, RealmDetail, Settings } from "@/lib/types";
import { PAGES } from "@/lib/pages";
import { SettingsForm } from "./settings-form";

export const metadata = { title: PAGES.settings.title };

export default async function SettingsPage({ params }: { params: Promise<{ realm: string }> }) {
  const { realm } = await params;
  const [me, settings, realmInfo] = await Promise.all([
    getMe(),
    load<Settings>(apiPath(["realms", realm, "settings"])),
    load<RealmDetail>(apiPath(["realms", realm])),
  ]);
  if (!settings.ok) return <ErrorState error={settings} />;
  const base = `/r/${encodeURIComponent(realm)}`;

  return (
    <>
      <PageHeader {...PAGES.settings} />
      <SettingsForm realm={realm} settings={settings.data} writable={me.ok && canWrite(me.data, "settings")} />
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        {realmInfo.ok && (
          <Card>
            <CardTitle>Realm</CardTitle>
            <div className="mt-4 flex items-start justify-between gap-4">
              <div>
                <p className="text-[14px] font-medium">{realmInfo.data.display_name}</p>
                <p className="font-mono text-[12px] text-text-muted">{realmInfo.data.name}</p>
                <p className="mt-1 text-[12px] text-text-muted">Created {formatDate(realmInfo.data.created_at)}</p>
              </div>
              <div className="flex gap-1">
                {realmInfo.data.system && <Badge tone="neutral">System realm</Badge>}
                <StatusBadge status={realmInfo.data.status} />
              </div>
            </div>
            <NavLink
              href={`${base}/realms`}
              className="mt-4 inline-block text-[13px] font-medium text-accent hover:underline"
            >
              Manage realms
            </NavLink>
          </Card>
        )}
        {me.ok && can(me.data, "realm") && (
          // Streamed: the form shows at once, the health checks arrive after.
          <Suspense fallback={<InfrastructureSkeleton />}>
            <Infrastructure realm={realm} />
          </Suspense>
        )}
      </div>
    </>
  );
}

async function Infrastructure({ realm }: { realm: string }) {
  const dashboard = await load<Dashboard>(apiPath(["realms", realm, "dashboard"]));
  if (!dashboard.ok) return null;
  return (
    <Card>
      <CardTitle>Infrastructure status</CardTitle>
      <ul className="mt-4 divide-y divide-border">
        {dashboard.data.infrastructure.map((i) => (
          <li key={i.name} className="flex items-center justify-between gap-4 py-2.5">
            <div className="min-w-0">
              <p className="text-[14px]">{i.name}</p>
              <p className="truncate text-[12px] text-text-muted" title={i.detail}>
                {i.status === "healthy" ? `${i.latency_ms} ms` : (i.detail ?? "Not configured")}
              </p>
            </div>
            <StatusBadge
              status={i.status}
              label={i.status === "healthy" ? "Operational" : i.status === "down" ? "Down" : "Not configured"}
            />
          </li>
        ))}
      </ul>
    </Card>
  );
}

function InfrastructureSkeleton() {
  return (
    <Card>
      <CardTitle>Infrastructure status</CardTitle>
      <div className="mt-4 space-y-3">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    </Card>
  );
}
