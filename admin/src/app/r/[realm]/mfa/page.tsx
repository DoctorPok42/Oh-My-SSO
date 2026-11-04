import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { ManagedBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Chips } from "@/components/ui/chip-select";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { TogglePill } from "@/components/ui/toggle-pill";
import { apiPath, getMe, load } from "@/lib/api";
import { MFA_METHOD_LABELS } from "@/lib/labels";
import { canWrite } from "@/lib/permissions";
import { PAGES } from "@/lib/pages";
import type { MfaPolicies } from "@/lib/types";
import { RealmMfaCard, RolePolicyActions } from "./mfa-forms";
import type { Translator } from "@/i18n";
import { getI18n } from "@/i18n/server";
import { ColumnHeads } from "@/components/console/skeletons";
import { COLUMNS } from "@/lib/pages";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.mfa.title) };
}

const methodChips = (ms: string[], { tm }: Translator) =>
  ms.map((id) => {
    const label = MFA_METHOD_LABELS[id];
    return { id, name: label ? tm(label).split(" (")[0]! : id };
  });

export default async function MfaPage({ params }: { params: Promise<{ realm: string }> }) {
  const { realm } = await params;
  const [me, res] = await Promise.all([getMe(), load<MfaPolicies>(apiPath(["realms", realm, "mfa-policies"]))]);
  if (!res.ok) return <ErrorState error={res} />;
  const p = res.data;
  const writable = me.ok && canWrite(me.data, "mfa_policy");
  const base = `/r/${encodeURIComponent(realm)}`;
  const tr = await getI18n();
  const { t } = tr;

  return (
    <>
      <PageHeader {...PAGES.mfa} />
      <RealmMfaCard realm={realm} policies={p} writable={writable} system={realm === "master"} />

      <h2 className="mt-8 mb-3 text-[15px] font-semibold">{t("mfa.per_role", "Per role")}</h2>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <ColumnHeads columns={COLUMNS.mfaRoles} />
            </TableRow>
          </TableHeader>
          <TableBody>
            {p.roles.length === 0 && (
              <TableEmpty colSpan={7}>{t("clients.access.no_role", "No role in this realm.")}</TableEmpty>
            )}
            {p.roles.map((r) => (
              <TableRow key={r.role.id}>
                <TableCell className="font-medium">
                  <span className="flex items-center gap-2">
                    {r.role.name}
                    <ManagedBadge managedBy={r.managed_by} />
                  </span>
                </TableCell>
                <TableCell>
                  <Badge tone={r.configured ? "accent" : "neutral"}>
                    {r.configured ? t("mfa.own_rules", "Own rules") : t("mfa.realm_default", "Realm default")}
                  </Badge>
                </TableCell>
                <TableCell>
                  <TogglePill
                    checked={r.required || p.required_globally}
                    onLabel={t("clients.scope.required", "Required")}
                    offLabel={t("clients.scope.optional", "Optional")}
                    label={t("columns.mfa_required", "MFA required")}
                  />
                </TableCell>
                <TableCell>
                  <TogglePill
                    checked={r.step_up_for_sensitive_actions}
                    label={t("columns.step_up", "Step-up for sensitive actions")}
                  />
                </TableCell>
                <TableCell className="text-text-secondary">
                  {r.configured ? tr.tn("mfa.grace_days", r.enrollment_grace_days, "{count} day", "{count} days") : "—"}
                </TableCell>
                <TableCell>
                  <Chips items={methodChips(r.allowed_methods, tr)} empty={t("mfa.any", "Any")} />
                </TableCell>
                <TableCell className="text-right">
                  <RolePolicyActions realm={realm} policy={r} known={p.known_methods} writable={writable} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <h2 className="mt-8 mb-1 text-[15px] font-semibold">{t("mfa.per_client", "Per client")}</h2>
      <p className="mb-3 text-[13px] text-text-secondary">
        {t("mfa.per_client_hint", "Read-only here: change a client's policy in its drawer:")}{" "}
        <NavLink href={`${base}/clients`} className="text-accent hover:underline">
          {t("pages.clients.title", "Clients")}
        </NavLink>
      </p>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <ColumnHeads columns={COLUMNS.mfaClients} />
            </TableRow>
          </TableHeader>
          <TableBody>
            {p.clients.length === 0 && <TableEmpty colSpan={3}>{t("mfa.no_client", "No client.")}</TableEmpty>}
            {p.clients.map((c) => (
              <TableRow key={c.client.id}>
                <TableCell>
                  <NavLink
                    href={`${base}/clients?edit=${encodeURIComponent(c.client.id)}`}
                    className="font-medium hover:underline"
                  >
                    {c.client.name}
                  </NavLink>
                </TableCell>
                <TableCell>
                  <Badge tone={c.policy === "required" ? "accent" : "neutral"}>
                    {c.policy === "required"
                      ? t("mfa.always_required", "Always required")
                      : t("mfa.inherit", "Inherit")}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Chips items={methodChips(c.methods, tr)} empty={t("mfa.any", "Any")} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}
