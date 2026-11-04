import { english, type Translator } from "@/i18n";

// Display helpers. Server Components render them once, on the server; the
// time zone is the server's unless TZ is set (UTC in the Docker image).
// Dates follow the console's language (locale: "en", "fr"...; English dates
// are written the British way, day first).

const formatters = new Map<string, { dateTime: Intl.DateTimeFormat; dateOnly: Intl.DateTimeFormat }>();

function formattersFor(locale = "en") {
  let f = formatters.get(locale);
  if (!f) {
    const tag = locale === "en" ? "en-GB" : locale;
    f = {
      dateTime: new Intl.DateTimeFormat(tag, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        timeZoneName: "short",
      }),
      dateOnly: new Intl.DateTimeFormat(tag, { year: "numeric", month: "short", day: "2-digit" }),
    };
    formatters.set(locale, f);
  }
  return f;
}

export function formatDateTime(iso: string | null | undefined, locale?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 1971 ? "—" : formattersFor(locale).dateTime.format(d);
}

export function formatDate(iso: string | null | undefined, locale?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 1971 ? "—" : formattersFor(locale).dateOnly.format(d);
}

/** "3 min ago", "in 2 h", "just now". */
export function formatRelative(
  iso: string | null | undefined,
  now: Date = new Date(),
  tr: Translator = english,
): string {
  const { t } = tr;
  if (!iso) return t("time.never", "never");
  const d = new Date(iso);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return t("time.never", "never");
  const s = Math.round((d.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(s);
  if (abs < 45) return t("time.just_now", "just now");
  let text: string;
  if (abs < 3600) text = t("time.minutes", "{n} min", { n: Math.max(1, Math.round(abs / 60)) });
  else if (abs < 86400) text = t("time.hours", "{n} h", { n: Math.round(abs / 3600) });
  else if (abs < 86400 * 60) text = t("time.days", "{n} d", { n: Math.round(abs / 86400) });
  else return formatDate(iso, tr.locale);
  return s < 0 ? t("time.ago", "{time} ago", { time: text }) : t("time.in", "in {time}", { time: text });
}

/** A percentage in 0..100 (the API's unit): "98.5%", "100%". */
export function formatPercent(p: number): string {
  if (!Number.isFinite(p)) return "—";
  return `${p.toFixed(p >= 99.95 || p === 0 || Number.isInteger(p) ? 0 : 1)}%`;
}

/** "1–20 of 43". */
export function pageLabel(offset: number, count: number, total: number, tr: Translator = english): string {
  if (total === 0) return tr.t("pagination.none", "0 of 0");
  return tr.t("pagination.range", "{from}–{to} of {total}", { from: offset + 1, to: offset + count, total });
}

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
