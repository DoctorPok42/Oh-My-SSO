import { Suspense } from "react";
import { NavLink } from "@/components/console/nav-link";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { offsetParam, Pagination } from "@/components/console/pagination";
import { SearchForm } from "@/components/console/search-form";
import { TableSkeleton } from "@/components/console/skeletons";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { SegmentedLinks } from "@/components/ui/segmented";
import { Table, TableBody, TableContainer, TableEmpty, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, load, loadCached } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { ACTOR_TYPE_LABELS } from "@/lib/labels";
import { COLUMNS, PAGES } from "@/lib/pages";
import type { AuditAction, AuditEntry, List } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AuditRows } from "./audit-rows";
import { ExportMenu } from "./export-menu";

export const metadata = { title: PAGES.audit.title };

const LIMIT = 50;

type Search = {
  status?: string;
  action?: string;
  actor?: string;
  user?: string;
  client?: string;
  from?: string;
  to?: string;
  offset?: string;
};

const ACTOR_TYPES = ["user", "admin", "cli", "system", "anonymous"];

// Every sensitive action of the realm, newest first. Filters are URL
// parameters (a GET form): a filtered view can be bookmarked or shared.
// The title and the filters show at once; the table loads on its own
// (keyed Suspense: a new filter or page shows a table skeleton only).
export default async function AuditPage({
  params,
  searchParams,
}: {
  params: Promise<{ realm: string }>;
  searchParams: Promise<Search>;
}) {
  const { realm } = await params;
  const sp = await searchParams;
  const status = sp.status === "success" || sp.status === "failure" ? sp.status : undefined;
  const actor = sp.actor && ACTOR_TYPES.includes(sp.actor) ? sp.actor : undefined;
  const offset = offsetParam(sp.offset);
  const filters = { status, action: sp.action, actor, user: sp.user, client: sp.client, from: sp.from, to: sp.to };
  const base = `/r/${encodeURIComponent(realm)}/audit`;
  const withStatus = (s?: string) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...filters, status: s })) if (v) q.set(k, v);
    const qs = q.toString();
    return qs ? `${base}?${qs}` : base;
  };
  // The catalogue of actions: the filter's suggestions and the labels.
  const catalog = await loadCached<{ items: AuditAction[] }>(apiPath(["realms", realm, "audit-logs", "actions"]));
  const actions = catalog.ok ? catalog.data.items : [];
  // "auth.*", "user.*"...: every action of a domain at once.
  const domains = [...new Map(actions.map((a) => [a.name.split(".")[0], a.category])).entries()];

  return (
    <>
      <PageHeader {...PAGES.audit} actions={<ExportMenu base={base} filters={filters} />} />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <SegmentedLinks
          label="Status"
          items={[
            { href: withStatus(undefined), label: "All", active: !status },
            { href: withStatus("success"), label: "Success", active: status === "success" },
            { href: withStatus("failure"), label: "Failed", active: status === "failure" },
          ]}
        />
        <SearchForm action={base} className="ml-auto flex flex-wrap items-end gap-2">
          {status && <input type="hidden" name="status" value={status} />}
          {sp.client && <input type="hidden" name="client" value={sp.client} />}
          <label className="flex flex-col text-[12px] text-text-muted">
            Action
            <Input
              name="action"
              list="audit-actions"
              defaultValue={sp.action}
              placeholder="Any action"
              autoComplete="off"
              className="mt-1 h-9 w-60 font-mono text-[12px]"
            />
            <datalist id="audit-actions">
              {domains.map(([prefix, category]) => (
                <option key={`${prefix}.*`} value={`${prefix}.*`} label={`${category}: every ${prefix}.* action`} />
              ))}
              {actions.map((a) => (
                <option key={a.name} value={a.name} label={`${a.category}: ${a.label}`} />
              ))}
            </datalist>
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            Done by
            <NativeSelect name="actor" defaultValue={actor ?? ""} className="mt-1 h-9 w-36 text-[13px]">
              <option value="">Anyone</option>
              {ACTOR_TYPES.map((t) => (
                <option key={t} value={t}>
                  {ACTOR_TYPE_LABELS[t]}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            User ID
            <Input
              name="user"
              defaultValue={sp.user}
              placeholder="done by or about"
              className="mt-1 h-9 w-44 font-mono text-[12px]"
            />
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            From
            <Input type="date" name="from" defaultValue={sp.from} className="mt-1 h-9 w-40" />
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            To
            <Input type="date" name="to" defaultValue={sp.to} className="mt-1 h-9 w-40" />
          </label>
          <button type="submit" className={cn(buttonVariants({ size: "sm" }))}>
            Apply
          </button>
          <NavLink href={base} className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
            Reset
          </NavLink>
        </SearchForm>
      </div>
      <Suspense
        key={JSON.stringify({ ...filters, offset })}
        fallback={<TableSkeleton columns={COLUMNS.audit} rows={10} />}
      >
        <AuditTable realm={realm} base={base} filters={filters} offset={offset} actions={actions} />
      </Suspense>
    </>
  );
}

async function AuditTable({
  realm,
  base,
  filters,
  offset,
  actions,
}: {
  realm: string;
  base: string;
  filters: Record<string, string | undefined>;
  offset: number;
  actions: AuditAction[];
}) {
  const list = await load<List<AuditEntry>>(
    apiPath(["realms", realm, "audit-logs"], { ...filters, offset, limit: LIMIT }),
  );
  if (!list.ok) return <ErrorState error={list} />;
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Timestamp</TableHead>
            <TableHead>Actor</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>IP</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {list.data.items.length === 0 && <TableEmpty colSpan={6}>No entry matches these filters.</TableEmpty>}
          <AuditRows
            items={list.data.items}
            times={Object.fromEntries(list.data.items.map((a) => [a.id, formatDateTime(a.timestamp)]))}
            actions={actions}
          />
        </TableBody>
      </Table>
      <Pagination
        basePath={base}
        params={filters}
        offset={offset}
        limit={LIMIT}
        count={list.data.items.length}
        total={list.data.total}
      />
    </TableContainer>
  );
}
