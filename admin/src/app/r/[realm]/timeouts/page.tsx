import { Suspense } from "react";
import { BulkCell, BulkHead } from "@/components/console/bulk";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { Pagination } from "@/components/console/pagination";
import { offsetParam } from "@/lib/pagination";
import { Badge } from "@/components/ui/badge";
import { SegmentedLinks } from "@/components/ui/segmented";
import { Table, TableBody, TableCell, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { BULK_ROW } from "@/lib/bulk";
import { apiPath, getMe, load, loadCached } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import { STATUS_BADGE, TARGET_LABELS } from "@/lib/timeout-form";
import type { List, Timeout } from "@/lib/types";
import { NewTimeoutButton, TimeoutDrawer, TimeoutRowActions } from "./timeout-drawer";
import { TimeoutsBulk } from "./bulk";
import { getI18n } from "@/i18n/server";
import { ColumnHeads } from "@/components/console/skeletons";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.timeouts.title) };
}

const LIMIT = 25;
type Status = "current" | "past" | "all";
type Search = {
  status?: string;
  offset?: string;
  new?: string;
  edit?: string;
  // Pre-filled target ("Suspend" in the user, group and client drawers).
  target_type?: string;
  target_id?: string;
  target_name?: string;
};

// Temporary suspensions of a user, a group or a client. The list shows the
// scheduled and active ones first; the drawer creates (?new=1), changes the
// reason or the end, and lifts (?edit=<id>).
export default async function TimeoutsPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const status: Status = sp.status === "past" || sp.status === "all" ? sp.status : "current";
  const offset = offsetParam(sp.offset);
  const base = `/r/${encodeURIComponent(realm)}/timeouts`;
  const me = await getMe();
  const writable = me.ok && canWrite(me.data, "timeout");
  const { t } = await getI18n();

  const filters = [
    { href: base, label: t("timeouts.filter.current", "Current"), active: status === "current" },
    { href: `${base}?status=past`, label: t("timeouts.filter.past", "Past"), active: status === "past" },
    { href: `${base}?status=all`, label: t("common.all", "All"), active: status === "all" },
  ];

  return (
    <>
      <PageHeader {...PAGES.timeouts} actions={writable && <NewTimeoutButton />} />
      <div className="mb-4">
        <SegmentedLinks label={t("timeouts.filter.label", "Which timeouts")} items={filters} />
      </div>
      <TimeoutsTable realm={realm} base={base} status={status} offset={offset} writable={writable} />
      <Suspense fallback={null}>
        <TimeoutDrawerSlot realm={realm} sp={sp} writable={writable} />
      </Suspense>
    </>
  );
}

async function TimeoutsTable({
  realm,
  base,
  status,
  offset,
  writable,
}: {
  realm: string;
  base: string;
  status: Status;
  offset: number;
  writable: boolean;
}) {
  const list = await loadCached<List<Timeout>>(
    apiPath(["realms", realm, "timeouts"], { status, offset, limit: LIMIT }),
  );
  if (!list.ok) return <ErrorState error={list} />;
  const { items, total } = list.data;
  const { t, tm, locale } = await getI18n();
  const empty =
    status === "current"
      ? t("timeouts.empty.current", "Nobody is suspended, and nothing is scheduled.")
      : status === "past"
        ? t("timeouts.empty.past", "No timeout has ended yet.")
        : t("timeouts.empty.all", "No timeout yet.");
  const liftable = (to: Timeout) => to.status === "active" || to.status === "scheduled";
  const bulk = writable && status !== "past";
  const table = (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            {bulk && <BulkHead />}
            <ColumnHeads columns={COLUMNS.timeouts} />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && <TableEmpty colSpan={bulk ? 8 : 7}>{empty}</TableEmpty>}
          {items.map((to) => {
            const badge = STATUS_BADGE[to.status] ?? STATUS_BADGE.ended;
            return (
              <TableRow key={to.id} className={BULK_ROW}>
                {bulk && (
                  <BulkCell
                    id={to.id}
                    label={to.target.name}
                    blocked={liftable(to) ? undefined : t("timeouts.over_bulk", "This timeout is over")}
                  />
                )}
                <TableCell>
                  <span className="flex items-center gap-2">
                    <Badge tone="neutral">
                      {TARGET_LABELS[to.target_type] ? tm(TARGET_LABELS[to.target_type]) : to.target_type}
                    </Badge>
                    <span className="font-medium">{to.target.name}</span>
                  </span>
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary">
                  {formatDateTime(to.starts_at, locale)}
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary">
                  {to.status === "lifted"
                    ? t("timeouts.lifted_at", "Lifted {when}", { when: formatDateTime(to.lifted_at, locale) })
                    : to.ends_at
                      ? formatDateTime(to.ends_at, locale)
                      : t("timeouts.end.none", "No end")}
                </TableCell>
                <TableCell className="max-w-[320px] truncate text-text-secondary" title={to.reason}>
                  {to.reason}
                </TableCell>
                <TableCell className="text-text-secondary">{to.created_by}</TableCell>
                <TableCell>
                  <Badge tone={badge.tone}>{tm(badge.label)}</Badge>
                </TableCell>
                <TableCell className="text-right">
                  <TimeoutRowActions realm={realm} timeout={to} writable={writable} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      {total > LIMIT && (
        <Pagination
          basePath={base}
          params={{ status: status === "current" ? undefined : status }}
          offset={offset}
          limit={LIMIT}
          count={items.length}
          total={total}
        />
      )}
    </TableContainer>
  );
  if (!bulk) return table;
  return (
    <TimeoutsBulk realm={realm} status={status} page={items.filter(liftable).map((to) => to.id)} total={total}>
      {table}
    </TimeoutsBulk>
  );
}

async function TimeoutDrawerSlot({ realm, sp, writable }: { realm: string; sp: Search; writable: boolean }) {
  const one = sp.edit ? await load<Timeout>(apiPath(["realms", realm, "timeouts", sp.edit])) : null;
  const editing = one?.ok ? one.data : null;
  return (
    <TimeoutDrawer
      realm={realm}
      mode={sp.new ? "create" : editing ? "edit" : null}
      timeout={editing}
      prefill={sp.new ? { type: sp.target_type, id: sp.target_id, name: sp.target_name } : undefined}
      writable={writable}
    />
  );
}
