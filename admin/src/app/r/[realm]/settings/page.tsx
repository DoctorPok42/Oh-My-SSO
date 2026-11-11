import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardTitle } from "@/components/ui/card";
import { apiPath, getMe, loadCached } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { can, canWrite } from "@/lib/permissions";
import { settingsSection, type SettingsSection } from "@/lib/settings-form";
import type { HealthLine, List, RealmDetail, Settings } from "@/lib/types";
import { PAGES } from "@/lib/pages";
import { offsetParam } from "@/lib/pagination";
import { LockedAccounts } from "./locked-accounts";
import { SettingsForm } from "./settings-form";
import { getI18n } from "@/i18n/server";

const SECTIONS = {
  general: PAGES.settingsGeneral,
  security: PAGES.settingsSecurity,
  sessions: PAGES.settingsSessions,
  email: PAGES.settingsEmail,
  audit: PAGES.settingsAudit,
} satisfies Record<SettingsSection, unknown>;

type Search = { tab?: string; offset?: string };

export async function generateMetadata({ searchParams }: { searchParams: Promise<Search> }) {
  const { tm } = await getI18n();
  return { title: tm(SECTIONS[settingsSection((await searchParams).tab)].title) };
}

// Every sub-page needs settings:read, so the menu shows them all or none. The
// realm and infrastructure cards need realm:read as well: without it they are
// left out, and not asked for (a refused call writes to the audit log).
export default async function SettingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const section = settingsSection(sp.tab);
  const me = await getMe();
  const showRealm = section === "general" && me.ok && can(me.data, "realm");
  const [settings, realmInfo] = await Promise.all([
    loadCached<Settings>(apiPath(["realms", realm, "settings"])),
    showRealm ? loadCached<RealmDetail>(apiPath(["realms", realm])) : null,
  ]);
  if (!settings.ok) return <ErrorState error={settings} />;
  const base = `/r/${encodeURIComponent(realm)}`;
  const { t, locale } = await getI18n();

  return (
    <>
      <PageHeader {...SECTIONS[section]} />
      <SettingsForm
        realm={realm}
        settings={settings.data}
        writable={me.ok && canWrite(me.data, "settings")}
        section={section}
        realmCard={
          realmInfo?.ok && (
            <Card>
              <CardTitle>{t("settings.realm.title", "Realm")}</CardTitle>
              <div className="mt-4 flex items-start justify-between gap-4">
                <div>
                  <p className="text-[14px] font-medium">{realmInfo.data.display_name}</p>
                  <p className="font-mono text-[12px] text-text-muted">{realmInfo.data.name}</p>
                  <p className="mt-1 text-[12px] text-text-muted">
                    {t("common.created_on", "Created {date}", { date: formatDate(realmInfo.data.created_at, locale) })}
                  </p>
                </div>
                <div className="flex gap-1">
                  {realmInfo.data.system && <Badge tone="neutral">{t("settings.realm.system", "System realm")}</Badge>}
                  <StatusBadge status={realmInfo.data.status} />
                </div>
              </div>
              <NavLink
                href={`${base}/realms`}
                className="mt-4 inline-block text-[13px] font-medium text-accent hover:underline"
              >
                {t("realm_switcher.manage", "Manage realms")}
              </NavLink>
            </Card>
          )
        }
        infrastructure={
          // The Admin API never waits long for the health checks (cachedHealth).
          showRealm && <Infrastructure />
        }
      />
      {section === "security" && me.ok && can(me.data, "user") && (
        <LockedAccounts realm={realm} writable={canWrite(me.data, "user")} offset={offsetParam(sp.offset)} />
      )}
    </>
  );
}

async function Infrastructure() {
  const lines = await loadCached<List<HealthLine>>("/infrastructure");
  if (!lines.ok) return null;
  const { t } = await getI18n();
  return (
    <Card>
      <CardTitle>{t("settings.infrastructure", "Infrastructure status")}</CardTitle>
      <ul className="mt-4 divide-y divide-border">
        {lines.data.items.map((i) => (
          <li key={i.name} className="flex items-center justify-between gap-4 py-2.5">
            <div className="min-w-0">
              <p className="text-[14px]">{i.name}</p>
              <p className="truncate text-[12px] text-text-muted" title={i.detail}>
                {i.status === "healthy"
                  ? `${i.latency_ms} ms`
                  : (i.detail ?? t("status.not_configured", "Not configured"))}
              </p>
            </div>
            <StatusBadge
              status={i.status}
              label={
                i.status === "healthy"
                  ? t("dashboard.operational", "Operational")
                  : i.status === "down"
                    ? t("status.down", "Down")
                    : t("status.not_configured", "Not configured")
              }
            />
          </li>
        ))}
      </ul>
    </Card>
  );
}
