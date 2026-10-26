import { NavLink } from "@/components/console/nav-link";
import { X } from "lucide-react";
import { Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { offsetParam, Pagination } from "@/components/console/pagination";
import { TableSkeleton } from "@/components/console/skeletons";
import { Badge } from "@/components/ui/badge";
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
import { apiPath, getMe, load } from "@/lib/api";
import { formatDateTime, formatRelative } from "@/lib/format";
import { AUTH_METHOD_LABELS, MFA_METHOD_LABELS } from "@/lib/labels";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import type { List, SessionRow } from "@/lib/types";
import { RevokeSessionButton } from "./revoke-button";

export const metadata = { title: PAGES.sessions.title };

const LIMIT = 25;

export default async function SessionsPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<{ user?: string; client?: string; offset?: string }>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const offset = offsetParam(sp.offset);
  return (
    <>
      <PageHeader {...PAGES.sessions} />
      {/* A new filter or page: a new key, so the table alone shows a skeleton. */}
      <Suspense
        key={`${sp.user}|${sp.client}|${offset}`}
        fallback={<TableSkeleton columns={COLUMNS.sessions} rows={8} />}
      >
        <SessionsTable realm={realm} user={sp.user} client={sp.client} offset={offset} />
      </Suspense>
    </>
  );
}

async function SessionsTable({
  realm,
  user,
  client,
  offset,
}: {
  realm: string;
  user?: string;
  client?: string;
  offset: number;
}) {
  const base = `/r/${encodeURIComponent(realm)}/sessions`;
  const [me, list] = await Promise.all([
    getMe(),
    load<List<SessionRow>>(apiPath(["realms", realm, "sessions"], { user, client, offset, limit: LIMIT })),
  ]);
  if (!list.ok) return <ErrorState error={list} />;
  const revocable = me.ok && canWrite(me.data, "session");
  const items = list.data.items;
  const filtered = user || client;

  return (
    <>
      {filtered && (
        <div className="mb-4 flex items-center gap-2 text-[13px] text-text-secondary">
          Filtered by {user ? "user" : "client"}
          <Badge tone="accent" className="font-mono">
            {items[0] && user ? items[0].user.name : (user ?? client)}
          </Badge>
          <NavLink href={base} className="inline-flex items-center gap-1 text-accent hover:underline">
            <X className="size-3.5" /> Clear
          </NavLink>
        </div>
      )}
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>IP address</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Applications</TableHead>
              <TableHead>Auth method</TableHead>
              <TableHead>MFA</TableHead>
              <TableHead>Last active</TableHead>
              <TableHead>Expires</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && <TableEmpty colSpan={9}>No active session.</TableEmpty>}
            {items.map((s) => (
              <TableRow key={s.id}>
                <TableCell>
                  <NavLink
                    href={`${base}?user=${encodeURIComponent(s.user.id)}`}
                    className="font-medium hover:underline"
                  >
                    {s.user.name}
                  </NavLink>
                  <p className="text-[12px] text-text-muted">{s.user_email}</p>
                </TableCell>
                <TableCell className="font-mono text-[12px] text-text-secondary">{s.ip_address || "—"}</TableCell>
                <TableCell className="text-text-secondary" title={s.user_agent}>
                  {s.device || "Unknown"}
                </TableCell>
                <TableCell className="text-text-secondary">
                  {s.clients.length === 0 ? "—" : s.clients.map((c) => c.name).join(", ")}
                </TableCell>
                <TableCell className="text-text-secondary">
                  {AUTH_METHOD_LABELS[s.auth_method] ?? s.auth_method}
                </TableCell>
                <TableCell>
                  {s.mfa_verified ? (
                    <Badge tone="success">{MFA_METHOD_LABELS[s.mfa_method]?.split(" (")[0] ?? "Verified"}</Badge>
                  ) : (
                    <Badge tone="neutral">No</Badge>
                  )}
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary" title={formatDateTime(s.last_activity_at)}>
                  {formatRelative(s.last_activity_at)}
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary" title={formatDateTime(s.expires_at)}>
                  {formatRelative(s.expires_at)}
                </TableCell>
                <TableCell className="text-right">
                  {revocable && <RevokeSessionButton realm={realm} id={s.id} user={s.user.name} />}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <Pagination
          basePath={base}
          params={{ user, client }}
          offset={offset}
          limit={LIMIT}
          count={items.length}
          total={list.data.total}
        />
      </TableContainer>
    </>
  );
}
