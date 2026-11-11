// Bulk actions: what does not depend on React (the selection, the summary of
// a result). The API takes at most the realm's bulk limit at a time (Settings,
// BULK_LIMIT until it is changed, GET /realms/{realm}/bulk-limit); a larger
// selection is done in passes, each one confirmed.

/** The bulk limit of a realm that has not changed it. */
export const BULK_LIMIT = 100;
/** The highest bulk limit the Settings accept. */
export const MAX_BULK_LIMIT = 500;

/** For a <TableRow> holding a BulkCell: the selected row stands out. */
export const BULK_ROW = "has-[[data-bulk-row][data-state=checked]]:bg-accent-soft/50";

/**
 * A bulk action runs in the background of idp-admin (POST .../bulk answers at
 * once with the job, GET /realms/{realm}/bulk-jobs/{id} follows it): this is
 * how often the console asks where it stands.
 */
export const BULK_POLL_MS = 1_000;
/** The first look comes sooner: a small selection is often over by then. */
export const BULK_FIRST_POLL_MS = 250;

/** The largest page the Admin API answers. */
const API_PAGE = 200;

export type BulkItem = {
  id: string;
  label: string;
  /** not_run, unknown: the server stopped before / while working on the item. */
  status: "done" | "skipped" | "failed" | "not_run" | "unknown";
  code?: string;
  message?: string;
};

/** A bulk action: where it stands while it runs, its report (items) once it is over. */
export type BulkJob = {
  id: string;
  operation_id: string;
  action: string;
  status: "running" | "completed" | "interrupted";
  total: number;
  processed: number;
  done: number;
  skipped: number;
  failed: number;
  /** Items the server stopped before: an interrupted job only. */
  not_run: number;
  items: BulkItem[];
  created_at: string;
  finished_at: string | null;
};

/** What the summary of a bulk action needs: a finished job. */
export type BulkResult = Pick<BulkJob, "operation_id" | "action" | "done" | "skipped" | "failed" | "items"> &
  Partial<Pick<BulkJob, "status" | "not_run">>;

/** What POST .../bulk takes. */
export type BulkBody = { action: string; ids: string[]; reason?: string; group_id?: string; role_id?: string };

/** Adds or removes one id; nothing is added past the limit. */
export function toggleId(selected: readonly string[], id: string, limit = BULK_LIMIT): string[] {
  if (selected.includes(id)) return selected.filter((x) => x !== id);
  return selected.length >= limit ? [...selected] : [...selected, id];
}

/** The "select all" of a page: everything selected unselects it, otherwise it fills up to the limit. */
export function togglePage(selected: readonly string[], page: readonly string[], limit = BULK_LIMIT): string[] {
  if (page.length > 0 && page.every((id) => selected.includes(id))) {
    return selected.filter((id) => !page.includes(id));
  }
  const out = [...selected];
  for (const id of page) {
    if (out.length >= limit) break;
    if (!out.includes(id)) out.push(id);
  }
  return out;
}

/** The state of the "select all" box. */
export function pageState(selected: readonly string[], page: readonly string[]): boolean | "indeterminate" {
  const picked = page.filter((id) => selected.includes(id)).length;
  if (picked === 0) return false;
  return picked === page.length ? true : "indeterminate";
}

export type BulkReason = { code: string; message: string; count: number };

/** Why items were not changed, one line per reason, the most frequent first. */
export function bulkReasons(items: readonly BulkItem[]): BulkReason[] {
  const out = new Map<string, BulkReason>();
  for (const item of items) {
    if (item.status === "done") continue;
    const code = item.code ?? item.status;
    const reason = out.get(code);
    if (reason) reason.count++;
    else out.set(code, { code, message: item.message ?? code, count: 1 });
  }
  return [...out.values()].sort((a, b) => b.count - a.count);
}

export function bulkTone(
  r: Pick<BulkResult, "done" | "skipped" | "failed" | "not_run">,
): "success" | "warning" | "danger" {
  if (r.failed > 0) return "danger";
  return r.skipped > 0 || (r.not_run ?? 0) > 0 ? "warning" : "success";
}

/** Whole percent of a running job, 0 to 100. */
export function bulkPercent(job: Pick<BulkJob, "processed" | "total">): number {
  if (job.total <= 0) return 0;
  return Math.min(100, Math.round((job.processed / job.total) * 100));
}

type IdPage<T> = { items: T[]; total: number };

/**
 * The ids of a filter, up to `limit`, leaving out `exclude` (rows that cannot
 * be selected, and those an earlier pass already went through: they may still
 * match the filter). The ids are read now, so what the action does next
 * cannot shift the pages under it. `keep` leaves out the rows that cannot be
 * selected, when the row itself tells.
 */
export async function collectIds<T extends { id: string }>(
  fetchPage: (offset: number, limit: number) => Promise<IdPage<T>>,
  exclude: readonly string[],
  keep: (row: T) => boolean = () => true,
  limit = BULK_LIMIT,
): Promise<string[]> {
  const out: string[] = [];
  for (let offset = 0; out.length < limit; offset += API_PAGE) {
    const page = await fetchPage(offset, API_PAGE);
    for (const row of page.items) {
      if (out.length < limit && keep(row) && !exclude.includes(row.id)) out.push(row.id);
    }
    if (page.items.length < API_PAGE || offset + page.items.length >= page.total) break;
  }
  return out;
}

/** The usernames or e-mails of a pasted list, each once. */
export function parseIdentifiers(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).filter(Boolean))];
}

export type BulkSelection = {
  selected: string[];
  /** The selection came from "select the results of the filter". */
  fromFilter: boolean;
  /** What the earlier passes went through. */
  seen: string[];
};

export const EMPTY_SELECTION: BulkSelection = { selected: [], fromFilter: false, seen: [] };

/** A bulk limit read from the API: anything out of range is the default. */
export function bulkLimitOf(v: unknown): number {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= MAX_BULK_LIMIT ? v : BULK_LIMIT;
}

/** What sessionStorage holds; anything else counts as an empty selection. */
export function parseSelection(raw: string | null | undefined, limit = BULK_LIMIT): BulkSelection {
  if (!raw) return EMPTY_SELECTION;
  try {
    const v = JSON.parse(raw) as Partial<BulkSelection>;
    const ids = (x: unknown) => (Array.isArray(x) ? x.filter((id): id is string => typeof id === "string") : []);
    return { selected: ids(v.selected).slice(0, limit), fromFilter: v.fromFilter === true, seen: ids(v.seen) };
  } catch {
    return EMPTY_SELECTION;
  }
}
