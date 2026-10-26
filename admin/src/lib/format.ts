// Display helpers. Server Components render them once, on the server; the
// time zone is the server's unless TZ is set (UTC in the Docker image).

const dateTime = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short",
});
const dateOnly = new Intl.DateTimeFormat("en-GB", { year: "numeric", month: "short", day: "2-digit" });

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 1971 ? "—" : dateTime.format(d);
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 1971 ? "—" : dateOnly.format(d);
}

/** "3 min ago", "in 2 h", "just now". */
export function formatRelative(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return "never";
  const s = Math.round((d.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(s);
  if (abs < 45) return "just now";
  let text: string;
  if (abs < 3600) text = `${Math.max(1, Math.round(abs / 60))} min`;
  else if (abs < 86400) text = `${Math.round(abs / 3600)} h`;
  else if (abs < 86400 * 60) text = `${Math.round(abs / 86400)} d`;
  else return formatDate(iso);
  return s < 0 ? `${text} ago` : `in ${text}`;
}

/** A percentage in 0..100 (the API's unit): "98.5%", "100%". */
export function formatPercent(p: number): string {
  if (!Number.isFinite(p)) return "—";
  return `${p.toFixed(p >= 99.95 || p === 0 || Number.isInteger(p) ? 0 : 1)}%`;
}

/** "1–20 of 43". */
export function pageLabel(offset: number, count: number, total: number): string {
  if (total === 0) return "0 of 0";
  return `${offset + 1}–${offset + count} of ${total}`;
}

// --- token lifetimes: the API speaks seconds, people think in minutes and days ---

export function secondsTo(unit: "minutes" | "hours" | "days", seconds: number): string {
  if (!seconds) return "";
  const div = unit === "minutes" ? 60 : unit === "hours" ? 3600 : 86400;
  return String(Math.round((seconds / div) * 100) / 100);
}

export function toSeconds(unit: "minutes" | "hours" | "days", value: string): number {
  const n = Number(value.trim().replace(",", "."));
  if (!value.trim() || !Number.isFinite(n) || n <= 0) return 0; // 0 = server default
  const mul = unit === "minutes" ? 60 : unit === "hours" ? 3600 : 86400;
  return Math.round(n * mul);
}

/** One entry per non-empty line (redirect URIs, IP allowlists...). */
export function lines(v: string): string[] {
  return v
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

export function initials(name: string): string {
  const parts = name
    .trim()
    .split(/[\s._@-]+/)
    .filter(Boolean);
  const first = parts[0]?.[0] ?? "?";
  const second = parts.length > 1 ? (parts[1]?.[0] ?? "") : "";
  return (first + second).toUpperCase();
}

export function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}
