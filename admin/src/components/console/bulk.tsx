"use client";

import { ChevronDown, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { toast } from "sonner";
import { NavLink } from "@/components/console/nav-link";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { useBulkJob } from "@/components/console/use-bulk-job";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { TableCell, TableHead } from "@/components/ui/table";
import { useT } from "@/i18n/client";
import type { ApiResult } from "@/lib/api-error";
import {
  BULK_LIMIT,
  bulkPercent,
  bulkReasons,
  bulkTone,
  EMPTY_SELECTION,
  pageState,
  parseSelection,
  toggleId,
  togglePage,
  type BulkJob,
  type BulkResult,
  type BulkSelection,
} from "@/lib/bulk";

// Bulk actions on a table. The rows stay Server Components: only their
// checkboxes are client islands, and BulkProvider around the table holds the
// selection, the action bar, the confirmation and the summary of the result.
//
// The selection outlives the page: it survives the pagination and the round
// trip to the IdP of a step-up (a full navigation), so it is kept in
// sessionStorage, per table and filters.

export type BulkParams = { reason?: string; pick?: string };

type BulkActionBase = {
  id: string;
  label: string;
  /** Red, and confirmed in red. */
  danger?: boolean;
  /** In the "More" menu, to keep the bar short. */
  overflow?: boolean;
};

/** Changes nothing (an export): no confirmation, no step-up, no summary. */
export type BulkDirectAction = BulkActionBase & { direct: (ids: string[]) => void | Promise<void> };

export type BulkConfirmedAction = BulkActionBase & {
  direct?: undefined;
  title: (count: number) => string;
  description: string;
  /** To be typed before the action can run. */
  confirmWord?: string;
  /** Asks for a reason, written to the audit log. */
  reason?: boolean;
  /** Asks to choose one group or role. */
  picker?: { label: string; options: { id: string; name: string }[] };
  run: (ids: string[], params: BulkParams) => Promise<ApiResult<BulkJob>>;
};

export type BulkAction = BulkDirectAction | BulkConfirmedAction;

type Context = {
  selected: readonly string[];
  page: readonly string[];
  toggle: (id: string) => void;
  toggleAll: () => void;
};

const Ctx = createContext<Context | null>(null);

const LimitCtx = createContext(BULK_LIMIT);

/** The realm's bulk limit (Settings), for every selection below (the realm layout). */
export function BulkLimitProvider({ limit, children }: { limit: number; children: ReactNode }) {
  return <LimitCtx.Provider value={limit}>{children}</LimitCtx.Provider>;
}

/** The most items one bulk action of this realm may touch. */
export function useBulkLimit(): number {
  return useContext(LimitCtx);
}

function useBulk(): Context {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("bulk checkbox outside <BulkProvider>");
  return ctx;
}

// sessionStorage can refuse (private window, blocked site data): the memory
// keeps the selection for as long as the page lives.
const memory = new Map<string, string>();
const listeners = new Set<() => void>();

function readRaw(key: string): string | null {
  const held = memory.get(key);
  if (held !== undefined) return held;
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeRaw(key: string, next: BulkSelection) {
  const raw = JSON.stringify(next);
  memory.set(key, raw);
  try {
    if (next.selected.length === 0 && next.seen.length === 0) sessionStorage.removeItem(key);
    else sessionStorage.setItem(key, raw);
  } catch {
    // The memory has it.
  }
  listeners.forEach((l) => l());
}

function subscribe(onChange: () => void) {
  listeners.add(onChange);
  return () => {
    listeners.delete(onChange);
  };
}

function useSelection(key: string, limit: number) {
  const raw = useSyncExternalStore(
    subscribe,
    () => readRaw(key),
    () => null,
  );
  const selection = useMemo(() => parseSelection(raw, limit), [raw, limit]);
  const save = useCallback((next: BulkSelection) => writeRaw(key, next), [key]);
  return [selection, save] as const;
}

export function BulkProvider({
  scope,
  realm,
  page,
  total,
  countLabel,
  doneLabel,
  actions,
  matching,
  children,
}: {
  /** The table and its filters: another filter is another selection. */
  scope: string;
  realm: string;
  /** The ids of this page that can be selected. */
  page: string[];
  /** How many rows match the filters, on every page. */
  total: number;
  countLabel: (count: number) => string;
  doneLabel: (count: number) => string;
  actions: BulkAction[];
  /** The ids of the filter, without those given. */
  matching?: (exclude: string[]) => Promise<ApiResult<string[]>>;
  children: ReactNode;
}) {
  const { t } = useT();
  const stepUp = useStepUp();
  const { run, pending } = useAction();
  const { progress, follow } = useBulkJob(realm);
  const search = useSearchParams();
  const limit = useBulkLimit();
  const [selection, save] = useSelection(`omsso.bulk.${scope}`, limit);
  const { selected, fromFilter, seen } = selection;
  const reopen = search.get("bulk");
  const [dialogId, setDialogId] = useState<string | null>(reopen);
  const [result, setResult] = useState<{ data: BulkResult; action: BulkConfirmedAction; more: boolean } | null>(null);
  const [selecting, setSelecting] = useState(false);

  // Back from a step-up: the dialog is open, the URL goes back to normal.
  useEffect(() => {
    if (!reopen) return;
    const url = new URL(window.location.href);
    url.searchParams.delete("bulk");
    window.history.replaceState(null, "", url);
  }, [reopen]);

  const context = useMemo<Context>(
    () => ({
      selected,
      page,
      toggle: (id) => {
        setResult(null);
        save({ selected: toggleId(selected, id, limit), fromFilter: false, seen: [] });
      },
      toggleAll: () => {
        setResult(null);
        save({ selected: togglePage(selected, page, limit), fromFilter: false, seen: [] });
      },
    }),
    [selected, page, save, limit],
  );

  const open = (action: BulkAction) => {
    if (action.direct) void action.direct([...selected]);
    else stepUp.ensure(() => setDialogId(action.id), `bulk=${action.id}`);
  };

  const selectMatching = async (exclude: string[], then?: BulkConfirmedAction) => {
    if (!matching) return;
    setSelecting(true);
    const r = await matching(exclude);
    setSelecting(false);
    if (!r.ok) {
      toast.error(r.message);
      return;
    }
    if (r.data.length === 0) {
      setResult(null);
      toast.info(t("bulk.nothing_left", "Nothing left to do."));
      return;
    }
    setResult(null);
    save({ selected: r.data, fromFilter: true, seen: exclude });
    if (then) open(then);
  };

  const action = actions.find((a): a is BulkConfirmedAction => a.id === dialogId && !a.direct && selected.length > 0);
  const pageSelected = page.length > 0 && page.every((id) => selected.includes(id));

  return (
    <Ctx.Provider value={context}>
      {(result || progress || selected.length > 0) && (
        <div className="mb-3 space-y-2">
          {progress && <BulkRunning job={progress} />}
          {result && (
            <BulkSummary
              realm={realm}
              result={result.data}
              doneLabel={doneLabel}
              more={result.more}
              busy={selecting}
              onNext={() => selectMatching(selection.seen, result.action)}
              onDismiss={() => setResult(null)}
            />
          )}
          {selected.length > 0 && (
            <BulkBar
              label={countLabel(selected.length)}
              actions={actions}
              onAction={open}
              onClear={() => save(EMPTY_SELECTION)}
              selectAll={
                matching && pageSelected && !fromFilter && total > selected.length ? (
                  <Button
                    variant="link"
                    size="xs"
                    className={BAR_LINK}
                    loading={selecting}
                    onClick={() => selectMatching([])}
                  >
                    {total > limit
                      ? t("bulk.select_first", "Select the first {limit} of {total} results", {
                          limit,
                          total,
                        })
                      : t("bulk.select_all", "Select all {total} results", { total })}
                  </Button>
                ) : null
              }
            />
          )}
        </div>
      )}
      {children}
      {action && (
        <BulkConfirm
          key={action.id}
          action={action}
          count={selected.length}
          pending={pending}
          onCancel={() => setDialogId(null)}
          onConfirm={async (params) => {
            const ids = [...selected];
            // The API answers once the job is recorded: it runs in the background.
            const r = await run(() => action.run(ids, params), { intent: `bulk=${action.id}` });
            setDialogId(null);
            if (!r.ok) return;
            save({ selected: [], fromFilter: false, seen: [...seen, ...ids] });
            setResult(null);
            const job = await follow(r.data);
            if (!job) return;
            if (job.status === "interrupted") {
              // What the server did not get to is still to do: the next pass finds it again.
              const left = new Set(
                job.items.filter((i) => i.status === "not_run" || i.status === "unknown").map((i) => i.id),
              );
              save({ selected: [], fromFilter: false, seen: [...seen, ...ids.filter((id) => !left.has(id))] });
            }
            setResult({ data: job, action, more: fromFilter && ids.length === limit && job.status === "completed" });
          }}
        />
      )}
    </Ctx.Provider>
  );
}

// The bar is tinted (accent-soft): the buttons get an opaque surface (no border)
// and a focus ring that contrasts with the tint (the default ring is
// accent-soft, invisible here).
const BAR_BUTTON =
  "min-h-7 border-transparent bg-surface shadow-[var(--shadow)] hover:border-transparent hover:bg-row-hover focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-1 focus-visible:ring-offset-accent-soft";
const BAR_DANGER =
  "min-h-7 border-transparent bg-danger-soft text-danger hover:border-transparent hover:bg-danger hover:text-on-accent focus-visible:ring-2 focus-visible:ring-danger focus-visible:ring-offset-1 focus-visible:ring-offset-accent-soft";
const BAR_LINK =
  "rounded-sm focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-1 focus-visible:ring-offset-accent-soft";

function BulkBar({
  label,
  actions,
  onAction,
  onClear,
  selectAll,
}: {
  label: string;
  actions: BulkAction[];
  onAction: (a: BulkAction) => void;
  onClear: () => void;
  selectAll: ReactNode;
}) {
  const { t } = useT();
  const more = actions.filter((a) => a.overflow);
  return (
    <div
      role="toolbar"
      aria-label={t("bulk.toolbar", "Actions on the selection")}
      className="flex flex-wrap items-center gap-2 rounded-[10px] border border-accent bg-accent-soft px-3 py-2"
    >
      <span className="mr-1.5 text-[13px] font-semibold text-accent">{label}</span>
      {actions
        .filter((a) => !a.overflow)
        .map((a) => (
          <Button
            key={a.id}
            variant={a.danger ? "danger" : "secondary"}
            size="xs"
            className={a.danger ? BAR_DANGER : BAR_BUTTON}
            onClick={() => onAction(a)}
          >
            {a.label}
          </Button>
        ))}
      {more.length > 0 && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="secondary" size="xs" className={BAR_BUTTON}>
              {t("bulk.more", "More")} <ChevronDown className="size-3.5" aria-hidden />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="min-w-48">
            {more.map((a) => (
              <DropdownMenuItem
                key={a.id}
                className={
                  a.danger
                    ? "text-danger data-[highlighted]:bg-danger-soft"
                    : "data-[highlighted]:bg-accent-soft data-[highlighted]:text-accent"
                }
                onSelect={() => onAction(a)}
              >
                {a.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {selectAll}
      <Button
        variant="ghost"
        size="xs"
        className={`ml-auto text-text-primary hover:bg-surface ${BAR_LINK}`}
        onClick={onClear}
      >
        {t("bulk.clear", "Clear selection")}
      </Button>
    </div>
  );
}

function BulkConfirm({
  action,
  count,
  pending,
  onCancel,
  onConfirm,
}: {
  action: BulkConfirmedAction;
  count: number;
  pending: boolean;
  onCancel: () => void;
  onConfirm: (params: BulkParams) => void;
}) {
  const { t } = useT();
  const limit = useBulkLimit();
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [pick, setPick] = useState(action.picker?.options[0]?.id ?? "");
  const ready =
    (!action.confirmWord || typed.trim().toLowerCase() === action.confirmWord.toLowerCase()) &&
    (!action.reason || reason.trim() !== "") &&
    (!action.picker || pick !== "");
  return (
    <AlertDialog open onOpenChange={(o) => !o && onCancel()}>
      <AlertDialogContent>
        <AlertDialogTitle>{action.title(count)}</AlertDialogTitle>
        <AlertDialogDescription>{action.description}</AlertDialogDescription>
        <div className="mt-4 space-y-3">
          {action.picker && (
            <div>
              <Label htmlFor="bulk-pick">{action.picker.label}</Label>
              <NativeSelect id="bulk-pick" value={pick} onChange={(e) => setPick(e.target.value)}>
                {action.picker.options.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </NativeSelect>
            </div>
          )}
          {action.reason && (
            <div>
              <Label htmlFor="bulk-reason">{t("bulk.reason", "Reason (goes to the audit log)")}</Label>
              <Input id="bulk-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          )}
          {action.confirmWord && (
            <div>
              <Label htmlFor="bulk-word">
                {t("bulk.type_word", 'Type "{word}" to confirm', { word: action.confirmWord })}
              </Label>
              <Input
                id="bulk-word"
                value={typed}
                autoComplete="off"
                className="font-mono"
                placeholder={action.confirmWord}
                onChange={(e) => setTyped(e.target.value)}
              />
            </div>
          )}
          <p className="text-[12px] leading-5 text-text-muted">
            {t(
              "bulk.note",
              "Up to {limit} items per operation. Items that cannot be changed are skipped and listed in the summary. One audit entry is written per item, grouped under a single operation id.",
              { limit },
            )}
          </p>
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel>{t("common.cancel", "Cancel")}</AlertDialogCancel>
          <Button
            variant={action.danger ? "destructive" : "primary"}
            loading={pending}
            disabled={pending || !ready}
            onClick={() => onConfirm({ reason: reason.trim() || undefined, pick: pick || undefined })}
          >
            {pending ? t("common.working", "Working…") : action.label}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** A bulk action that runs in the background: how far it went. */
export function BulkRunning({ job }: { job: BulkJob }) {
  const { t } = useT();
  const percent = bulkPercent(job);
  return (
    <Banner tone="info" data-testid="bulk-progress">
      <div className="min-w-0 flex-1 space-y-1.5">
        <p className="font-semibold">
          {t("bulk.running", "Working… {processed} of {total}", { processed: job.processed, total: job.total })}
        </p>
        <div
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={t("bulk.progress", "Progress of the bulk action")}
          className="h-2 overflow-hidden rounded-full bg-neutral-soft"
        >
          <div className="h-full bg-accent transition-[width]" style={{ width: `${percent}%` }} />
        </div>
        <p className="text-[12px] text-text-secondary">
          {t("bulk.running_hint", "It goes on if you leave this page; the result is in the audit log.")}
        </p>
      </div>
    </Banner>
  );
}

export function BulkSummary({
  realm,
  result,
  doneLabel,
  more,
  busy,
  onNext,
  onDismiss,
}: {
  realm: string;
  result: BulkResult;
  doneLabel: (count: number) => string;
  more?: boolean;
  busy?: boolean;
  onNext?: () => void;
  onDismiss: () => void;
}) {
  const { t, tn } = useT();
  const reasons = bulkReasons(result.items);
  const others = result.items.filter((i) => i.status !== "done");
  const interrupted = result.status === "interrupted";
  const left = result.skipped + result.failed + (result.not_run ?? 0);
  // An interrupted job also leaves its own audit entry, naming what was not done.
  const entries = result.done + (interrupted ? 1 : 0);
  return (
    <Banner tone={bulkTone(result)} data-testid="bulk-result">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold">{doneLabel(result.done)}</p>
          {interrupted && (
            <p className="text-[12px] font-medium" data-testid="bulk-interrupted">
              {t(
                "bulk.interrupted",
                "The server stopped before the end: {count} not processed. Select them again to finish.",
                { count: result.not_run ?? 0 },
              )}
            </p>
          )}
          <p className="text-[12px] text-text-secondary">
            {left === 0
              ? t("bulk.nothing_skipped", "Nothing skipped.")
              : t("bulk.not_changed", "{count} not changed: {reasons}.", {
                  count: left,
                  reasons: reasons.map((r) => `${r.count} ${r.message}`).join(", "),
                })}{" "}
            {entries > 0 && (
              <NavLink
                href={`/r/${encodeURIComponent(realm)}/audit?operation=${encodeURIComponent(result.operation_id)}`}
                className="underline"
              >
                {tn("bulk.audit_link", entries, "See the audit entry", "See the {count} audit entries")}
              </NavLink>
            )}
          </p>
          {others.length > 0 && (
            <details className="mt-1 text-[12px] text-text-secondary">
              <summary>{t("bulk.details", "Details")}</summary>
              <ul className="mt-1 space-y-0.5">
                {others.map((i) => (
                  <li key={i.id}>
                    <span className="font-medium">{i.label}</span>: {i.message}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {more && (
            <Button variant="secondary" size="xs" className="mt-2" loading={busy} onClick={onNext}>
              {t("bulk.next", "Continue with the next results")}
            </Button>
          )}
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="size-6 shrink-0"
          aria-label={t("bulk.dismiss", "Dismiss")}
          onClick={onDismiss}
        >
          <X className="size-3.5" aria-hidden />
        </Button>
      </div>
    </Banner>
  );
}

/** The "select all" of the page, as a column head. */
export function BulkHead() {
  const { t } = useT();
  const { selected, page, toggleAll } = useBulk();
  return (
    <TableHead className="w-10 pr-0">
      <Checkbox
        aria-label={t("bulk.select_page", "Select all on this page")}
        checked={pageState(selected, page)}
        disabled={page.length === 0}
        onCheckedChange={toggleAll}
      />
    </TableHead>
  );
}

/** The checkbox of a row. A row that cannot be selected says why. */
export function BulkCell({ id, label, blocked }: { id: string; label: string; blocked?: string }) {
  const { t } = useT();
  const { selected, toggle } = useBulk();
  return (
    // The click stays here: a row can be clickable (the audit log's are).
    <TableCell className="w-10 pr-0" onClick={(e) => e.stopPropagation()}>
      <Checkbox
        data-bulk-row=""
        aria-label={blocked ?? t("bulk.select_row", "Select {name}", { name: label })}
        title={blocked}
        checked={selected.includes(id)}
        disabled={!!blocked}
        onCheckedChange={() => toggle(id)}
      />
    </TableCell>
  );
}
