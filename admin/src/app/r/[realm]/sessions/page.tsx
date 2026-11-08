import { NavLink } from "@/components/console/nav-link";
import { X } from "lucide-react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { Pagination } from "@/components/console/pagination";
import { offsetParam } from "@/lib/pagination";
import { SearchForm } from "@/components/console/search-form";
import { ColumnHeads } from "@/components/console/skeletons";
import { BulkCell, BulkHead } from "@/components/console/bulk";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, getMe, loadCached } from "@/lib/api";
import { BULK_ROW } from "@/lib/bulk";
import { formatDateTime, formatRelative } from "@/lib/format";
import { AUTH_METHOD_LABELS, MFA_METHOD_LABELS } from "@/lib/labels";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import type { List, SessionRow } from "@/lib/types";
import { cn } from "@/lib/utils";
import { SessionsBulk } from "./bulk";
import { RevokeSessionButton } from "./revoke-button";
import { getI18n } from "@/i18n/server";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.sessions.title) };
}

const LIMIT = 25;

export default async function SessionsPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<{ user?: string; client?: string; ip?: string; offset?: string }>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const offset = offsetParam(sp.offset);
  return (
    <>
      <PageHeader {...PAGES.sessions} />
      <SessionsTable realm={realm} user={sp.user} client={sp.client} ip={sp.ip} offset={offset} />
    </>
  );
}

async function SessionsTable({
  realm,
  user,
  client,
  ip,
  offset,
}: {
  realm: string;
  user?: string;
  client?: string;
  ip?: string;
  offset: number;
}) {
  const base = `/r/${encodeURIComponent(realm)}/sessions`;
  const [me, list] = await Promise.all([
    getMe(),
    loadCached<List<SessionRow>>(apiPath(["realms", realm, "sessions"], { user, client, ip, offset, limit: LIMIT })),
  ]);
  if (!list.ok) return <ErrorState error={list} />;
  const revocable = me.ok && canWrite(me.data, "session");
  const tr = await getI18n();
  const { t, tm, locale } = tr;
  const items = list.data.items;
  const filtered = user || client;
  const ownId = me.ok ? me.data.session_id : undefined;

  const table = (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            {revocable && <BulkHead />}
            <ColumnHeads columns={COLUMNS.sessions} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && (
            <TableEmpty colSpan={revocable ? 10 : 9}>{t("sessions.empty", "No active session.")}</TableEmpty>
          )}
          {items.map((s) => (
            <TableRow key={s.id} className={BULK_ROW}>
              {revocable && (
                <BulkCell
                  id={s.id}
                  label={s.user.name}
                  blocked={
                    s.id === ownId
                      ? t("sessions.own_session", "Your own session cannot be part of a bulk action")
                      : undefined
                  }
                />
              )}
              <TableCell>
                <NavLink href={`${base}?user=${encodeURIComponent(s.user.id)}`} className="font-medium hover:underline">
                  {s.user.name}
                </NavLink>
                <p className="text-[12px] text-text-muted">{s.user_email}</p>
              </TableCell>
              <TableCell className="font-mono text-[12px] text-text-secondary">{s.ip_address || "—"}</TableCell>
              <TableCell className="text-text-secondary" title={s.user_agent}>
                {s.device || t("sessions.unknown_device", "Unknown")}
              </TableCell>
              <TableCell className="text-text-secondary">
                {s.clients.length === 0 ? "—" : s.clients.map((c) => c.name).join(", ")}
              </TableCell>
              <TableCell className="text-text-secondary">
                {AUTH_METHOD_LABELS[s.auth_method] ? tm(AUTH_METHOD_LABELS[s.auth_method]!) : s.auth_method}
              </TableCell>
              <TableCell>
                {s.mfa_verified ? (
                  <Badge tone="success">
                    {MFA_METHOD_LABELS[s.mfa_method]
                      ? tm(MFA_METHOD_LABELS[s.mfa_method]!).split(" (")[0]
                      : t("sessions.mfa_verified", "Verified")}
                  </Badge>
                ) : s.trusted_device ? (
                  <Badge
                    tone="info"
                    title={t("sessions.trusted_hint", "Second factor skipped: Don't ask again on this device")}
                  >
                    {t("sessions.trusted", "Trusted device")}
                  </Badge>
                ) : (
                  <Badge tone="neutral">{t("common.no", "No")}</Badge>
                )}
              </TableCell>
              <TableCell
                className="whitespace-nowrap text-text-secondary"
                title={formatDateTime(s.last_activity_at, locale)}
              >
                {formatRelative(s.last_activity_at, undefined, tr)}
              </TableCell>
              <TableCell className="whitespace-nowrap text-text-secondary" title={formatDateTime(s.expires_at, locale)}>
                {formatRelative(s.expires_at, undefined, tr)}
                {s.remember_me && (
                  <Badge tone="info" className="ml-2" title={t("sessions.kept_hint", "Keep me signed in was ticked")}>
                    {t("sessions.kept", "Kept signed in")}
                  </Badge>
                )}
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
        params={{ user, client, ip }}
        offset={offset}
        limit={LIMIT}
        count={items.length}
        total={list.data.total}
      />
    </TableContainer>
  );

  return (
    <>
      <SearchForm action={base} className="mb-4 flex flex-wrap items-center gap-2" role="search">
        {user && <input type="hidden" name="user" value={user} />}
        {client && <input type="hidden" name="client" value={client} />}
        <Input
          name="ip"
          defaultValue={ip}
          placeholder={t("sessions.ip_placeholder", "IP address")}
          className="h-9 w-56 font-mono text-[13px]"
          aria-label={t("sessions.ip_label", "Filter by IP address")}
        />
        <button type="submit" className={cn(buttonVariants({ variant: "secondary", size: "sm" }))}>
          {t("common.search", "Search")}
        </button>
        {(filtered || ip) && (
          <NavLink href={base} className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline">
            <X className="size-3.5" /> {t("common.clear", "Clear")}
          </NavLink>
        )}
        {filtered && (
          <span className="ml-1 flex items-center gap-2 text-[13px] text-text-secondary">
            {user
              ? t("sessions.filtered_user", "Filtered by user")
              : t("sessions.filtered_client", "Filtered by client")}
            <Badge tone="accent" className="font-mono">
              {items[0] && user ? items[0].user.name : (user ?? client)}
            </Badge>
          </span>
        )}
      </SearchForm>
      {revocable ? (
        <SessionsBulk
          realm={realm}
          scope={`sessions:${realm}:${user ?? ""}:${client ?? ""}:${ip ?? ""}`}
          filter={{ user, client, ip }}
          page={items.map((s) => s.id).filter((id) => id !== ownId)}
          total={list.data.total}
          ownId={ownId}
        >
          {table}
        </SessionsBulk>
      ) : (
        table
      )}
    </>
  );
}
