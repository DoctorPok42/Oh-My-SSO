import { Suspense } from "react";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { offsetParam, Pagination } from "@/components/console/pagination";
import { TableSkeleton } from "@/components/console/skeletons";
import { Badge } from "@/components/ui/badge";
import { SegmentedLinks } from "@/components/ui/segmented";
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
import { formatDateTime } from "@/lib/format";
import { COLUMNS, PAGES } from "@/lib/pages";
import { canWrite } from "@/lib/permissions";
import { STATUS_BADGE, TARGET_LABELS } from "@/lib/timeout-form";
import type { List, Timeout } from "@/lib/types";
import { NewTimeoutButton, TimeoutDrawer, TimeoutRowActions } from "./timeout-drawer";

export const metadata = { title: PAGES.timeouts.title };

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

  const filters = [
    { href: base, label: "Current", active: status === "current" },
    { href: `${base}?status=past`, label: "Past", active: status === "past" },
    { href: `${base}?status=all`, label: "All", active: status === "all" },
  ];

  return (
    <>
      <PageHeader {...PAGES.timeouts} actions={writable && <NewTimeoutButton />} />
      <div className="mb-4">
        <SegmentedLinks label="Which timeouts" items={filters} />
      </div>
      <Suspense key={`${status}|${offset}`} fallback={<TableSkeleton columns={COLUMNS.timeouts} rows={4} />}>
        <TimeoutsTable realm={realm} base={base} status={status} offset={offset} writable={writable} />
      </Suspense>
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
  const list = await load<List<Timeout>>(apiPath(["realms", realm, "timeouts"], { status, offset, limit: LIMIT }));
  if (!list.ok) return <ErrorState error={list} />;
  const { items, total } = list.data;
  const empty =
    status === "current"
      ? "Nobody is suspended, and nothing is scheduled."
      : status === "past"
        ? "No timeout has ended yet."
        : "No timeout yet.";
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Target</TableHead>
            <TableHead>Start</TableHead>
            <TableHead>End</TableHead>
            <TableHead>Reason</TableHead>
            <TableHead>Created by</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 && <TableEmpty colSpan={7}>{empty}</TableEmpty>}
          {items.map((t) => {
            const badge = STATUS_BADGE[t.status] ?? STATUS_BADGE.ended;
            return (
              <TableRow key={t.id}>
                <TableCell>
                  <span className="flex items-center gap-2">
                    <Badge tone="neutral">{TARGET_LABELS[t.target_type] ?? t.target_type}</Badge>
                    <span className="font-medium">{t.target.name}</span>
                  </span>
                </TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary">{formatDateTime(t.starts_at)}</TableCell>
                <TableCell className="whitespace-nowrap text-text-secondary">
                  {t.status === "lifted"
                    ? `Lifted ${formatDateTime(t.lifted_at)}`
                    : t.ends_at
                      ? formatDateTime(t.ends_at)
                      : "No end"}
                </TableCell>
                <TableCell className="max-w-[320px] truncate text-text-secondary" title={t.reason}>
                  {t.reason}
                </TableCell>
                <TableCell className="text-text-secondary">{t.created_by}</TableCell>
                <TableCell>
                  <Badge tone={badge.tone}>{badge.label}</Badge>
                </TableCell>
                <TableCell className="text-right">
                  <TimeoutRowActions realm={realm} timeout={t} writable={writable} />
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
