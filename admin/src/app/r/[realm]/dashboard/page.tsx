import { Mail } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { StatusBadge } from "@/components/console/status-badge";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { CopyField } from "@/components/ui/copy-button";
import { getI18n } from "@/i18n/server";
import { apiPath, getMe, loadCached } from "@/lib/api";
import { formatPercent, formatRelative } from "@/lib/format";
import { actionLabel, actorName, isNotification } from "@/lib/labels";
import { firstReadablePage, pageHref } from "@/lib/nav";
import { PAGES } from "@/lib/pages";
import { can } from "@/lib/permissions";
import type { Dashboard } from "@/lib/types";
import { cn } from "@/lib/utils";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.dashboard.title) };
}

export default async function DashboardPage({ params }: Readonly<{ params: Promise<{ realm: string }> }>) {
  const { realm } = await params;
  // Every sign-in lands here: an admin without realm:read goes on to a page
  // they may read, without a refused call to the API.
  const me = await getMe();
  if (me.ok && !can(me.data, "realm")) {
    const readable = firstReadablePage(me.data);
    if (readable) redirect(pageHref(realm, readable));
  }
  const tr = await getI18n();
  const { t, tm } = tr;
  const res = await loadCached<Dashboard>(apiPath(["realms", realm, "dashboard"]));
  if (!res.ok) return <ErrorState error={res} />;
  const d = res.data;
  const attempts = d.logins_24h.success + d.logins_24h.failure;
  const jwtKey = d.signing_keys.find((k) => k.purpose === "jwt_signing" && k.status === "active");
  const base = `/r/${encodeURIComponent(realm)}`;

  return (
    <>
      <PageHeader
        title={tm(PAGES.dashboard.title)}
        description={t("dashboard.description", "Identity provider overview for {realm}", {
          realm: d.realm.display_name,
        })}
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label={t("dashboard.active_sessions", "Active sessions")}
          value={d.active_sessions}
          href={`${base}/sessions`}
        />
        <Kpi
          label={t("dashboard.connected_clients", "Connected clients")}
          value={d.active_clients}
          href={`${base}/clients`}
        />
        <Kpi
          label={t("dashboard.login_success", "Login success (24h)")}
          value={attempts ? formatPercent(d.logins_24h.success_rate) : "—"}
          hint={
            attempts
              ? t("dashboard.login_success_hint", "{success} of {total} sign-ins", {
                  success: d.logins_24h.success,
                  total: attempts,
                })
              : t("dashboard.no_login", "No sign-in in the last 24 hours")
          }
        />
        <Kpi
          label={t("dashboard.failed_logins", "Failed logins (24h)")}
          value={d.logins_24h.failure}
          tone={d.logins_24h.failure > 0 ? "danger" : undefined}
          href={`${base}/audit?status=failure`}
        />
      </div>

      <Card className="mt-4 py-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <span className="text-[13px] font-semibold text-text-secondary">
            {t("dashboard.infrastructure", "Infrastructure")}
          </span>
          {d.infrastructure.map((i) => (
            <span key={i.name} className="inline-flex items-center gap-2 text-[13px]" title={i.detail}>
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
              <span>{i.name}</span>
              {i.status === "healthy" && (
                <span className="font-mono text-[11px] text-text-muted">{i.latency_ms} ms</span>
              )}
            </span>
          ))}
        </div>
      </Card>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>{t("dashboard.recent_activity", "Recent audit activity")}</CardTitle>
            <Link href={`${base}/audit`} className="text-[13px] font-medium text-accent hover:underline">
              {t("dashboard.view_all", "View all")}
            </Link>
          </CardHeader>
          {d.recent_activity.length === 0 ? (
            <p className="py-6 text-center text-[13px] text-text-muted">
              {t("dashboard.no_activity", "No activity yet.")}
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {d.recent_activity.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-4 py-3">
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 truncate text-[14px] font-medium">
                      {isNotification(a.action) && (
                        <Mail className="size-3.5 text-text-muted" aria-label={t("dashboard.email", "e-mail")} />
                      )}
                      {actionLabel(a.action, undefined, tr)}
                    </p>
                    <p className="text-[12px] text-text-muted">
                      {actorName(a, tr)} · {formatRelative(a.timestamp, undefined, tr)}
                    </p>
                  </div>
                  <StatusBadge status={a.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <div className="space-y-4">
          <Card>
            <CardTitle>{t("dashboard.signing_key", "Signing key")}</CardTitle>
            {jwtKey ? (
              <>
                <p className="mt-3 truncate font-mono text-[13px]" title={jwtKey.kid}>
                  {jwtKey.kid}
                </p>
                <p className="mt-1 text-[12px] text-text-muted">
                  {t("dashboard.key_since", "{alg} · active since {when}", {
                    alg: jwtKey.key_type === "EC" ? "ES256" : "RS256",
                    when: formatRelative(jwtKey.created_at, undefined, tr),
                  })}
                </p>
              </>
            ) : (
              <p className="mt-3 text-[13px] text-warning">
                {t("dashboard.no_key", "No active signing key: tokens cannot be issued.")}
              </p>
            )}
          </Card>
          <Card>
            <CardTitle>{t("dashboard.mfa_coverage", "MFA coverage")}</CardTitle>
            <div
              className="mt-4 h-2 overflow-hidden rounded-full bg-neutral-soft"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(d.mfa.percent)}
              aria-label={t("dashboard.mfa_coverage", "MFA coverage")}
            >
              <div className="h-full rounded-full bg-accent" style={{ width: `${Math.min(100, d.mfa.percent)}%` }} />
            </div>
            <p className="mt-2 text-[12px] text-text-muted">
              {t("dashboard.mfa_enrolled", "{percent} of users enrolled ({enrolled} of {total})", {
                percent: formatPercent(d.mfa.percent),
                enrolled: d.mfa.enrolled,
                total: d.mfa.total,
              })}
            </p>
          </Card>
        </div>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>{t("dashboard.endpoints", "Endpoints of this realm")}</CardTitle>
        </CardHeader>
        <dl className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {[
            [t("dashboard.oidc_issuer", "OIDC issuer"), d.realm.issuer],
            [t("dashboard.jwks", "JWKS (public keys)"), d.realm.jwks_url],
            [t("dashboard.saml_metadata", "SAML metadata"), d.realm.saml_metadata_url],
          ].map(([label, url]) => (
            <div key={label}>
              <dt className="mb-1.5 text-[13px] font-semibold text-text-secondary">{label}</dt>
              <dd>
                <CopyField value={url!} />
              </dd>
            </div>
          ))}
        </dl>
      </Card>
    </>
  );
}

function Kpi({
  label,
  value,
  hint,
  href,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  href?: string;
  tone?: "danger";
}) {
  const body = (
    <>
      <p className="text-[13px] text-text-muted">{label}</p>
      <p className={cn("mt-2 text-[28px] leading-none font-semibold", tone === "danger" && "text-danger")}>{value}</p>
      {hint && <p className="mt-2 text-[12px] text-text-muted">{hint}</p>}
    </>
  );
  return href ? (
    <Link
      href={href}
      className="block rounded-xl border border-border bg-surface p-5 shadow-elevation transition-colors hover:border-border-strong"
    >
      {body}
    </Link>
  ) : (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-elevation">{body}</div>
  );
}
