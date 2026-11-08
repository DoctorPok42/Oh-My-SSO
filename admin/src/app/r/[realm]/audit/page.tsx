import { NavLink } from "@/components/console/nav-link";
import { BulkHead } from "@/components/console/bulk";
import { ErrorState } from "@/components/console/error-state";
import { PageHeader } from "@/components/console/page-header";
import { Pagination } from "@/components/console/pagination";
import { offsetParam } from "@/lib/pagination";
import { SearchForm } from "@/components/console/search-form";
import { ColumnHeads } from "@/components/console/skeletons";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { SegmentedLinks } from "@/components/ui/segmented";
import { Table, TableBody, TableContainer, TableEmpty, TableHeader, TableRow } from "@/components/ui/table";
import { apiPath, loadCached } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { ACTOR_TYPE_LABELS, actionLabel, categoryLabel } from "@/lib/labels";
import { COLUMNS, PAGES } from "@/lib/pages";
import type { AuditAction, AuditEntry, List } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AuditRows } from "./audit-rows";
import { AuditBulk } from "./bulk";
import { ExportMenu } from "./export-menu";
import { getI18n } from "@/i18n/server";

export async function generateMetadata() {
  const { tm } = await getI18n();
  return { title: tm(PAGES.audit.title) };
}

const LIMIT = 50;

type Search = {
  status?: string;
  action?: string;
  actor?: string;
  user?: string;
  client?: string;
  operation?: string;
  from?: string;
  to?: string;
  offset?: string;
};

const ACTOR_TYPES = ["user", "admin", "cli", "system", "anonymous"];

// Every sensitive action of the realm, newest first. Filters are URL
// parameters (a GET form): a filtered view can be bookmarked or shared.
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
  const filters = {
    status,
    action: sp.action,
    actor,
    user: sp.user,
    client: sp.client,
    operation: sp.operation,
    from: sp.from,
    to: sp.to,
  };
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
  const tr = await getI18n();
  const { t, tm } = tr;

  return (
    <>
      <PageHeader {...PAGES.audit} actions={<ExportMenu base={base} filters={filters} />} />
      {sp.operation && (
        <div className="mb-4 flex items-center gap-2 text-[13px] text-text-secondary">
          {t("audit.filtered_operation", "One bulk action")}
          <Badge tone="accent" className="font-mono">
            {sp.operation}
          </Badge>
          <NavLink href={base} className="text-accent hover:underline">
            {t("common.clear", "Clear")}
          </NavLink>
        </div>
      )}
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <SegmentedLinks
          label={t("columns.status", "Status")}
          items={[
            { href: withStatus(undefined), label: t("common.all", "All"), active: !status },
            { href: withStatus("success"), label: t("status.success", "Success"), active: status === "success" },
            { href: withStatus("failure"), label: t("audit.failed", "Failed"), active: status === "failure" },
          ]}
        />
        <SearchForm action={base} className="ml-auto flex flex-wrap items-end gap-2">
          {status && <input type="hidden" name="status" value={status} />}
          {sp.client && <input type="hidden" name="client" value={sp.client} />}
          {sp.operation && <input type="hidden" name="operation" value={sp.operation} />}
          <label className="flex flex-col text-[12px] text-text-muted">
            {t("columns.action", "Action")}
            <Input
              name="action"
              list="audit-actions"
              defaultValue={sp.action}
              placeholder={t("audit.any_action", "Any action")}
              autoComplete="off"
              className="mt-1 h-9 w-60 font-mono text-[12px]"
            />
            <datalist id="audit-actions">
              {domains.map(([prefix, category]) => (
                <option
                  key={`${prefix}.*`}
                  value={`${prefix}.*`}
                  label={t("audit.every_action", "{category}: every {prefix}.* action", {
                    category: categoryLabel(category ?? "", tr),
                    prefix: prefix ?? "",
                  })}
                />
              ))}
              {actions.map((a) => (
                <option
                  key={a.name}
                  value={a.name}
                  label={`${categoryLabel(a.category, tr)}: ${actionLabel(a.name, new Map([[a.name, a.label]]), tr)}`}
                />
              ))}
            </datalist>
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            {t("audit.done_by", "Done by")}
            <NativeSelect
              name="actor"
              defaultValue={actor ?? ""}
              wrapperClassName="mt-1 w-36"
              className="h-9 text-[13px]"
            >
              <option value="">{t("audit.anyone", "Anyone")}</option>
              {ACTOR_TYPES.map((type) => (
                <option key={type} value={type}>
                  {tm(ACTOR_TYPE_LABELS[type]!)}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            {t("audit.user_id", "User ID")}
            <Input
              name="user"
              defaultValue={sp.user}
              placeholder={t("audit.user_id_placeholder", "done by or about")}
              className="mt-1 h-9 w-44 font-mono text-[12px]"
            />
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            {t("audit.from", "From")}
            <Input type="date" name="from" defaultValue={sp.from} className="mt-1 h-9 w-40" />
          </label>
          <label className="flex flex-col text-[12px] text-text-muted">
            {t("audit.to", "To")}
            <Input type="date" name="to" defaultValue={sp.to} className="mt-1 h-9 w-40" />
          </label>
          <button type="submit" className={cn(buttonVariants({ size: "sm" }))}>
            {t("common.apply", "Apply")}
          </button>
          <NavLink href={base} className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}>
            {t("common.reset", "Reset")}
          </NavLink>
        </SearchForm>
      </div>
      <AuditTable realm={realm} base={base} filters={filters} offset={offset} actions={actions} />
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
  const list = await loadCached<List<AuditEntry>>(
    apiPath(["realms", realm, "audit-logs"], { ...filters, offset, limit: LIMIT }),
  );
  if (!list.ok) return <ErrorState error={list} />;
  const { t, locale } = await getI18n();
  return (
    <AuditBulk realm={realm} base={base} page={list.data.items.map((a) => a.id)}>
      <TableContainer>
        <Table>
          <TableHeader>
            <TableRow>
              <BulkHead />
              <ColumnHeads columns={COLUMNS.audit} />
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.items.length === 0 && (
              <TableEmpty colSpan={7}>{t("audit.empty", "No entry matches these filters.")}</TableEmpty>
            )}
            <AuditRows
              items={list.data.items}
              times={Object.fromEntries(list.data.items.map((a) => [a.id, formatDateTime(a.timestamp, locale)]))}
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
    </AuditBulk>
  );
}
