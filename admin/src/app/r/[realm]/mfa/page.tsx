import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { ManagedBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { Chips } from "@/components/ui/chip-select";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableEmpty,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TogglePill } from "@/components/ui/toggle-pill";
import { apiPath, getMe, load } from "@/lib/api";
import { MFA_METHOD_LABELS } from "@/lib/labels";
import { canWrite } from "@/lib/permissions";
import { PAGES } from "@/lib/pages";
import type { MfaPolicies } from "@/lib/types";
import { RealmMfaCard, RolePolicyActions } from "./mfa-forms";

export const metadata = { title: PAGES.mfa.title };

const methodChips = (ms: string[]) => ms.map((m) => ({ id: m, name: MFA_METHOD_LABELS[m]?.split(" (")[0] ?? m }));

export default async function MfaPage({ params }: { params: Promise<{ realm: string }> }) {
  const { realm } = await params;
  const [me, res] = await Promise.all([getMe(), load<MfaPolicies>(apiPath(["realms", realm, "mfa-policies"]))]);
  if (!res.ok) return <ErrorState error={res} />;
  const p = res.data;
  const writable = me.ok && canWrite(me.data, "mfa_policy");
  const base = `/r/${encodeURIComponent(realm)}`;

  return (
    <>
      <PageHeader {...PAGES.mfa} />
      <RealmMfaCard realm={realm} policies={p} writable={writable} system={realm === "master"} />

      <h2 className="mt-8 mb-3 text-[15px] font-semibold">Per role</h2>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role</TableHead>
              <TableHead>Policy</TableHead>
              <TableHead>MFA required</TableHead>
              <TableHead>Step-up for sensitive actions</TableHead>
              <TableHead>Grace period</TableHead>
              <TableHead>Allowed methods</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {p.roles.length === 0 && <TableEmpty colSpan={7}>No role in this realm.</TableEmpty>}
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
                    {r.configured ? "Own rules" : "Realm default"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <TogglePill
                    checked={r.required || p.required_globally}
                    onLabel="Required"
                    offLabel="Optional"
                    label="MFA required"
                  />
                </TableCell>
                <TableCell>
                  <TogglePill checked={r.step_up_for_sensitive_actions} label="Step-up for sensitive actions" />
                </TableCell>
                <TableCell className="text-text-secondary">
                  {r.configured ? `${r.enrollment_grace_days} days` : "—"}
                </TableCell>
                <TableCell>
                  <Chips items={methodChips(r.allowed_methods)} empty="Any" />
                </TableCell>
                <TableCell className="text-right">
                  <RolePolicyActions realm={realm} policy={r} known={p.known_methods} writable={writable} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <h2 className="mt-8 mb-1 text-[15px] font-semibold">Per client</h2>
      <p className="mb-3 text-[13px] text-text-secondary">
        Read-only here: change a client&apos;s policy in{" "}
        <NavLink href={`${base}/clients`} className="text-accent hover:underline">
          Clients
        </NavLink>
        .
      </p>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Client</TableHead>
              <TableHead>Policy</TableHead>
              <TableHead>Accepted methods</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {p.clients.length === 0 && <TableEmpty colSpan={3}>No client.</TableEmpty>}
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
                    {c.policy === "required" ? "Always required" : "Inherit"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Chips items={methodChips(c.methods)} empty="Any" />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}
