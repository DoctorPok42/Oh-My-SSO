import type { Timeout, TimeoutStatus, TimeoutTargetType } from "@/lib/types";

// The timeout form's helpers (pure, unit-tested in tests/timeout-form.test.ts).
//
// Times: the form shows the admin's local time (<input type="datetime-local">,
// "2026-11-02T18:00", no zone); the Admin API speaks RFC 3339 in UTC.

export const TARGET_LABELS: Record<TimeoutTargetType, string> = { user: "User", group: "Group", client: "Client" };

/** How long: a shortcut, a date, or no end. */
export type EndChoice = "1h" | "24h" | "7d" | "date" | "none";

export const END_CHOICES: { value: EndChoice; label: string }[] = [
  { value: "1h", label: "1 hour" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "date", label: "Until a date" },
  { value: "none", label: "No end" },
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
): { body: TimeoutCreateBody } | { field: string; message: string } {
  if (!d.targetId) return { field: "target_id", message: `Choose the ${d.targetType} to suspend.` };
  const reason = d.reason.trim();
  if (!reason) return { field: "reason", message: "A reason is required: it is what the audit log keeps." };

  let start = now;
  const body: TimeoutCreateBody = { target_type: d.targetType, target_id: d.targetId, reason };
  if (d.startLater) {
    const s = fromLocalInput(d.startAt);
    if (!s) return { field: "starts_at", message: "Choose when it starts." };
    if (s.getTime() <= now.getTime()) return { field: "starts_at", message: "The start is in the past: choose “Now”." };
    start = s;
    body.starts_at = s.toISOString();
  }
  const end = endDate(d.end, d.endAt, start);
  if (end === "invalid") return { field: "ends_at", message: "Choose when it ends." };
  if (end) {
    if (end.getTime() < start.getTime() + 60_000)
      return { field: "ends_at", message: "The end must come at least a minute after the start." };
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
  t: Pick<Timeout, "reason" | "ends_at">,
  reason: string,
  end: "keep" | "none" | "date",
  endAt: string,
): { body: { reason?: string; ends_at?: string } } | { field: string; message: string } | null {
  const body: { reason?: string; ends_at?: string } = {};
  const r = reason.trim();
  if (!r) return { field: "reason", message: "A reason is required." };
  if (r !== t.reason) body.reason = r;
  if (end === "none" && t.ends_at !== null) body.ends_at = "";
  if (end === "date") {
    const d = fromLocalInput(endAt);
    if (!d) return { field: "ends_at", message: "Choose when it ends." };
    if (!t.ends_at || new Date(t.ends_at).getTime() !== d.getTime()) body.ends_at = d.toISOString();
  }
  return Object.keys(body).length ? { body } : null;
}

/** The badge of a status: a timeout in force is a restriction, hence red. */
export const STATUS_BADGE: Record<TimeoutStatus, { label: string; tone: "danger" | "warning" | "neutral" }> = {
  active: { label: "In force", tone: "danger" },
  scheduled: { label: "Scheduled", tone: "warning" },
  ended: { label: "Ended", tone: "neutral" },
  lifted: { label: "Lifted", tone: "neutral" },
};

/** What the admin is about to do, in one sentence. */
export function timeoutSummary(d: TimeoutDraft, fmt: (d: Date) => string, now: Date = new Date()): string {
  const who =
    d.targetType === "user"
      ? `${d.targetName || "This user"} cannot sign in or get a token`
      : d.targetType === "group"
        ? `No member of ${d.targetName || "this group"} can sign in or get a token`
        : `Nobody can sign in to ${d.targetName || "this application"}`;
  const s = d.startLater ? fromLocalInput(d.startAt) : null;
  const start = s ?? now;
  const from = d.startLater && s ? ` from ${fmt(s)}` : "";
  const end = endDate(d.end, d.endAt, start);
  const until = end === null ? " until the timeout is lifted" : end === "invalid" ? "" : ` until ${fmt(end)}`;
  return `${who}${from}${until}.`;
}

/** What happens at the start, for the drawer's explanation. */
export function signOutNote(type: TimeoutTargetType, later: boolean): string {
  const when = later ? "When it starts," : "At once,";
  return type === "client"
    ? `${when} every token issued to this application is revoked. Users keep their sign-in to other applications.`
    : `${when} ${type === "group" ? "every member is" : "the user is"} signed out everywhere (sessions and tokens revoked).`;
}

/** The toast after a create: what happened at the start. */
export function createdMessage(
  t: Pick<Timeout, "status" | "starts_at" | "target_type" | "sign_out" | "sign_out_pending">,
  fmt: (iso: string) => string,
): string {
  if (t.status === "scheduled") return `Timeout scheduled for ${fmt(t.starts_at)}`;
  if (t.sign_out_pending) return "Suspended. Signing out is retried in the background.";
  if (!t.sign_out) return "Suspended";
  if (t.target_type === "client") {
    const n = t.sign_out.tokens;
    return n === 0 ? "Suspended (no token to revoke)" : `Suspended: ${n} token${n === 1 ? "" : "s"} revoked`;
  }
  const n = t.sign_out.sessions;
  return n === 0 ? "Suspended (nobody was signed in)" : `Suspended: ${n} session${n === 1 ? "" : "s"} revoked`;
}

/** Can this timeout still change (reason, end, lift)? */
export function isCurrent(t: Pick<Timeout, "status">): boolean {
  return t.status === "active" || t.status === "scheduled";
}
