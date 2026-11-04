import { english, m, type Msg, type Translator } from "@/i18n";
import type { Timeout, TimeoutStatus, TimeoutTargetType } from "@/lib/types";

// The timeout form's helpers (pure, unit-tested in tests/timeout-form.test.ts).
//
// Times: the form shows the admin's local time (<input type="datetime-local">,
// "2026-11-02T18:00", no zone); the Admin API speaks RFC 3339 in UTC.
//
// Texts: in English unless a Translator is given (src/i18n).

export const TARGET_LABELS: Record<TimeoutTargetType, Msg> = {
  user: m("timeouts.target.user", "User"),
  group: m("timeouts.target.group", "Group"),
  client: m("timeouts.target.client", "Client"),
};

/** How long: a shortcut, a date, or no end. */
export type EndChoice = "1h" | "24h" | "7d" | "date" | "none";

export const END_CHOICES: { value: EndChoice; label: Msg }[] = [
  { value: "1h", label: m("timeouts.end.1h", "1 hour") },
  { value: "24h", label: m("timeouts.end.24h", "24 hours") },
  { value: "7d", label: m("timeouts.end.7d", "7 days") },
  { value: "date", label: m("timeouts.end.date", "Until a date") },
  { value: "none", label: m("timeouts.end.none", "No end") },
];

const HOUR = 3_600_000;
const LENGTHS: Record<"1h" | "24h" | "7d", number> = { "1h": HOUR, "24h": 24 * HOUR, "7d": 7 * 24 * HOUR };

export type TimeoutDraft = {
  targetType: TimeoutTargetType;
  targetId: string;
  targetName: string;
  startLater: boolean;
  startAt: string; // datetime-local, when startLater
  end: EndChoice;
  endAt: string; // datetime-local, when end === "date"
  reason: string;
};

export function emptyTimeoutDraft(prefill?: { type?: string; id?: string; name?: string }): TimeoutDraft {
  const type = prefill?.type === "group" || prefill?.type === "client" ? prefill.type : "user";
  return {
    targetType: type,
    targetId: prefill?.id ?? "",
    targetName: prefill?.name ?? "",
    startLater: false,
    startAt: "",
    end: "24h",
    endAt: "",
    reason: "",
  };
}

/** A datetime-local value ("2026-11-02T18:00", local time) as a Date; null if empty or invalid. */
export function fromLocalInput(v: string): Date | null {
  if (!v) return null;
  const d = new Date(v); // no zone in the string: local time (ECMA-262 Date Time String Format)
  return Number.isNaN(d.getTime()) ? null : d;
}

/** A Date as a datetime-local value, in local time, to the minute. */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export type TimeoutCreateBody = {
  target_type: TimeoutTargetType;
  target_id: string;
  reason: string;
  starts_at?: string;
  ends_at?: string;
};

/**
 * The body of POST /timeouts, or a problem to show next to a field. The
 * server checks everything again; this only catches what the admin can fix
 * before sending.
 */
export function timeoutBody(
  d: TimeoutDraft,
  now: Date = new Date(),
  { t }: Translator = english,
): { body: TimeoutCreateBody } | { field: string; message: string } {
  if (!d.targetId) {
    const message =
      d.targetType === "user"
        ? t("timeouts.error.choose_user", "Choose the user to suspend.")
        : d.targetType === "group"
          ? t("timeouts.error.choose_group", "Choose the group to suspend.")
          : t("timeouts.error.choose_client", "Choose the client to suspend.");
    return { field: "target_id", message };
  }
  const reason = d.reason.trim();
  if (!reason)
    return {
      field: "reason",
      message: t("timeouts.error.reason", "A reason is required: it is what the audit log keeps."),
    };

  let start = now;
  const body: TimeoutCreateBody = { target_type: d.targetType, target_id: d.targetId, reason };
  if (d.startLater) {
    const s = fromLocalInput(d.startAt);
    if (!s) return { field: "starts_at", message: t("timeouts.error.start", "Choose when it starts.") };
    if (s.getTime() <= now.getTime())
      return { field: "starts_at", message: t("timeouts.error.start_past", "The start is in the past: choose “Now”.") };
    start = s;
    body.starts_at = s.toISOString();
  }
  const end = endDate(d.end, d.endAt, start);
  if (end === "invalid") return { field: "ends_at", message: t("timeouts.error.end", "Choose when it ends.") };
  if (end) {
    if (end.getTime() < start.getTime() + 60_000)
      return {
        field: "ends_at",
        message: t("timeouts.error.end_soon", "The end must come at least a minute after the start."),
      };
    body.ends_at = end.toISOString();
  }
  return { body };
}

/** The end for a choice: a Date, null (no end), or "invalid" (no date given). */
export function endDate(choice: EndChoice, endAt: string, start: Date): Date | null | "invalid" {
  switch (choice) {
    case "none":
      return null;
    case "date":
      return fromLocalInput(endAt) ?? "invalid";
    default:
      return new Date(start.getTime() + LENGTHS[choice]);
  }
}

/**
 * The body of PATCH /timeouts/{id}: only what changed. ends_at "" removes
 * the end. null: nothing to send.
 */
export function timeoutPatch(
  timeout: Pick<Timeout, "reason" | "ends_at">,
  reason: string,
  end: "keep" | "none" | "date",
  endAt: string,
  { t }: Translator = english,
): { body: { reason?: string; ends_at?: string } } | { field: string; message: string } | null {
  const body: { reason?: string; ends_at?: string } = {};
  const r = reason.trim();
  if (!r) return { field: "reason", message: t("timeouts.error.reason_short", "A reason is required.") };
  if (r !== timeout.reason) body.reason = r;
  if (end === "none" && timeout.ends_at !== null) body.ends_at = "";
  if (end === "date") {
    const d = fromLocalInput(endAt);
    if (!d) return { field: "ends_at", message: t("timeouts.error.end", "Choose when it ends.") };
    if (!timeout.ends_at || new Date(timeout.ends_at).getTime() !== d.getTime()) body.ends_at = d.toISOString();
  }
  return Object.keys(body).length ? { body } : null;
}

/** The badge of a status: a timeout in force is a restriction, hence red. */
export const STATUS_BADGE: Record<TimeoutStatus, { label: Msg; tone: "danger" | "warning" | "neutral" }> = {
  active: { label: m("timeouts.status.active", "In force"), tone: "danger" },
  scheduled: { label: m("timeouts.status.scheduled", "Scheduled"), tone: "warning" },
  ended: { label: m("timeouts.status.ended", "Ended"), tone: "neutral" },
  lifted: { label: m("timeouts.status.lifted", "Lifted"), tone: "neutral" },
};

/** What the admin is about to do, in one sentence. */
export function timeoutSummary(
  d: TimeoutDraft,
  fmt: (d: Date) => string,
  now: Date = new Date(),
  { t }: Translator = english,
): string {
  const s = d.startLater ? fromLocalInput(d.startAt) : null;
  const start = s ?? now;
  const end = endDate(d.end, d.endAt, start);
  const values = { target: d.targetName, from: s ? fmt(s) : "", until: end instanceof Date ? fmt(end) : "" };
  const who =
    d.targetType === "user"
      ? d.targetName
        ? t("timeouts.summary.user", "{target} cannot sign in or get a token", values)
        : t("timeouts.summary.this_user", "This user cannot sign in or get a token")
      : d.targetType === "group"
        ? d.targetName
          ? t("timeouts.summary.group", "No member of {target} can sign in or get a token", values)
          : t("timeouts.summary.this_group", "No member of this group can sign in or get a token")
        : d.targetName
          ? t("timeouts.summary.client", "Nobody can sign in to {target}", values)
          : t("timeouts.summary.this_client", "Nobody can sign in to this application");
  const from = d.startLater && s ? t("timeouts.summary.from", " from {from}", values) : "";
  const until =
    end === null
      ? t("timeouts.summary.until_lifted", " until the timeout is lifted")
      : end === "invalid"
        ? ""
        : t("timeouts.summary.until", " until {until}", values);
  return `${who}${from}${until}.`;
}

/** What happens at the start, for the drawer's explanation. */
export function signOutNote(type: TimeoutTargetType, later: boolean, { t }: Translator = english): string {
  if (type === "client") {
    return later
      ? t(
          "timeouts.note.client_later",
          "When it starts, every token issued to this application is revoked. Users keep their sign-in to other applications.",
        )
      : t(
          "timeouts.note.client_now",
          "At once, every token issued to this application is revoked. Users keep their sign-in to other applications.",
        );
  }
  if (type === "group") {
    return later
      ? t(
          "timeouts.note.group_later",
          "When it starts, every member is signed out everywhere (sessions and tokens revoked).",
        )
      : t("timeouts.note.group_now", "At once, every member is signed out everywhere (sessions and tokens revoked).");
  }
  return later
    ? t("timeouts.note.user_later", "When it starts, the user is signed out everywhere (sessions and tokens revoked).")
    : t("timeouts.note.user_now", "At once, the user is signed out everywhere (sessions and tokens revoked).");
}

/** The toast after a create: what happened at the start. */
export function createdMessage(
  timeout: Pick<Timeout, "status" | "starts_at" | "target_type" | "sign_out" | "sign_out_pending">,
  fmt: (iso: string) => string,
  { t, tn }: Translator = english,
): string {
  if (timeout.status === "scheduled")
    return t("timeouts.created.scheduled", "Timeout scheduled for {when}", { when: fmt(timeout.starts_at) });
  if (timeout.sign_out_pending)
    return t("timeouts.created.pending", "Suspended. Signing out is retried in the background.");
  if (!timeout.sign_out) return t("timeouts.created.suspended", "Suspended");
  if (timeout.target_type === "client") {
    const n = timeout.sign_out.tokens;
    return n === 0
      ? t("timeouts.created.no_token", "Suspended (no token to revoke)")
      : tn("timeouts.created.tokens", n, "Suspended: {count} token revoked", "Suspended: {count} tokens revoked");
  }
  const n = timeout.sign_out.sessions;
  return n === 0
    ? t("timeouts.created.no_session", "Suspended (nobody was signed in)")
    : tn("timeouts.created.sessions", n, "Suspended: {count} session revoked", "Suspended: {count} sessions revoked");
}

/** Can this timeout still change (reason, end, lift)? */
export function isCurrent(t: Pick<Timeout, "status">): boolean {
  return t.status === "active" || t.status === "scheduled";
}
