"use client";

import { Ban, Search, X } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Badge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { useT } from "@/i18n/client";
import { formatDateTime } from "@/lib/format";
import {
  createdMessage,
  emptyTimeoutDraft,
  END_CHOICES,
  isCurrent,
  signOutNote,
  STATUS_BADGE,
  TARGET_LABELS,
  timeoutBody,
  timeoutPatch,
  timeoutSummary,
  toLocalInput,
  type EndChoice,
  type TimeoutDraft,
} from "@/lib/timeout-form";
import type { Timeout, TimeoutTargetType } from "@/lib/types";
import { createTimeout, liftTimeout, searchTimeoutTargets, updateTimeout, type TargetOption } from "./actions";

// The URL parameters that pre-fill the form (the "Suspend" links of the
// user, group and client drawers): dropped when the drawer closes.
const PREFILL = ["target_type", "target_id", "target_name"];

// The form's own fields: an error on one of them shows under it, any other
// error as a banner.
const FIELDS = ["target_id", "target_type", "reason", "starts_at", "ends_at"];

type Prefill = { type?: string; id?: string; name?: string };
type FormError = { field?: string; message: string } | null;
type EditEnd = "keep" | "none" | "date";

export function NewTimeoutButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  const { t } = useT();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Ban />
      {t("suspend.label", "Suspend…")}
    </Button>
  );
}

export function TimeoutRowActions({
  realm,
  timeout,
  writable,
}: {
  realm: string;
  timeout: Timeout;
  writable: boolean;
}) {
  const { openEdit } = useDrawerUrl();
  const current = isCurrent(timeout);
  const { t } = useT();
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(timeout.id)}>
        {writable && current ? t("common.edit", "Edit") : t("common.view", "View")}
      </Button>
      {writable && current && <LiftButton realm={realm} timeout={timeout} />}
    </div>
  );
}

function LiftButton({
  realm,
  timeout,
  size = "xs",
  onDone,
}: {
  realm: string;
  timeout: Timeout;
  size?: "xs" | "sm";
  onDone?: () => void;
}) {
  const scheduled = timeout.status === "scheduled";
  const { t } = useT();
  const name = timeout.target.name;
  return (
    <ConfirmAction
      size={size}
      variant="secondary"
      trigger={scheduled ? t("timeouts.cancel", "Cancel timeout") : t("timeouts.lift", "Lift")}
      title={
        scheduled
          ? t("timeouts.cancel_title", "Cancel this scheduled timeout?")
          : t("timeouts.lift_title", "Lift the timeout of {name}?", { name })
      }
      description={
        scheduled
          ? timeout.target_type === "user"
            ? t("timeouts.cancel_text_user", "It will never start: the user {name} is not signed out.", { name })
            : timeout.target_type === "group"
              ? t("timeouts.cancel_text_group", "It will never start: the group {name} is not signed out.", { name })
              : t("timeouts.cancel_text_client", "It will never start: the client {name} is not signed out.", { name })
          : timeout.target_type === "client"
            ? t("timeouts.lift_text_client", "People can sign in to this application again at once.")
            : t(
                "timeouts.lift_text",
                "Sign-ins work again at once. Sessions revoked when it started stay revoked: people sign in again.",
              )
      }
      confirmLabel={scheduled ? t("timeouts.cancel", "Cancel timeout") : t("timeouts.lift_confirm", "Lift timeout")}
      confirmVariant="primary"
      success={scheduled ? t("timeouts.cancelled", "Timeout cancelled") : t("timeouts.lifted", "Timeout lifted")}
      action={() => liftTimeout(realm, timeout.id)}
      onDone={onDone}
    />
  );
}

/**
 * One drawer for both: a new timeout (?new=1, maybe pre-filled), or one to
 * view, change or lift (?edit=<id>). Its state starts over for each item
 * opened (the "lastKey" pattern of the other drawers).
 */
export function TimeoutDrawer({
  realm,
  mode,
  timeout,
  prefill,
  writable,
}: {
  realm: string;
  mode: "create" | "edit" | null;
  timeout: Timeout | null;
  prefill?: Prefill;
  writable: boolean;
}) {
  const { closeDropping } = useDrawerUrl();
  const close = () => closeDropping(PREFILL);
  const { run, pending } = useAction();
  const tr = useT();
  const { t, tm, locale } = tr;
  const fmt = (d: Date) => formatDateTime(d.toISOString(), locale);

  const [draft, setDraft] = useState<TimeoutDraft>(() => emptyTimeoutDraft(prefill));
  const [reason, setReason] = useState(timeout?.reason ?? "");
  const [end, setEnd] = useState<EditEnd>("keep");
  const [endAt, setEndAt] = useState(timeout?.ends_at ? toLocalInput(new Date(timeout.ends_at)) : "");
  const [error, setError] = useState<FormError>(null);
  const [now, setNow] = useState(() => toLocalInput(new Date()));

  const key = mode === "create" ? `new:${prefill?.type ?? ""}:${prefill?.id ?? ""}` : (timeout?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(emptyTimeoutDraft(prefill));
    setReason(timeout?.reason ?? "");
    setEnd("keep");
    setEndAt(timeout?.ends_at ? toLocalInput(new Date(timeout.ends_at)) : "");
    setError(null);
    setNow(toLocalInput(new Date()));
  }

  const current = mode === "edit" && !!timeout && isCurrent(timeout);
  const intent = mode === "create" ? "new=1" : timeout ? `edit=${timeout.id}` : undefined;
  const { locked, banner } = useEditLock({ canWrite: writable && (mode === "create" || current), intent });
  const err = (f: string) => (error?.field === f ? error.message : undefined);
  const set = <K extends keyof TimeoutDraft>(k: K, v: TimeoutDraft[K]) => setDraft((d) => ({ ...d, [k]: v }));

  async function create() {
    setError(null);
    const b = timeoutBody(draft, undefined, tr);
    if ("field" in b) return setError(b);
    const r = await run(() => createTimeout(realm, b.body), { quiet: true, intent });
    if (!r.ok) return setError({ field: r.field, message: r.message });
    toast.success(createdMessage(r.data, (iso) => formatDateTime(iso, locale), tr));
    close();
  }

  async function save() {
    if (!timeout) return;
    setError(null);
    const p = timeoutPatch(timeout, reason, end, endAt, tr);
    if (p === null) return close();
    if ("field" in p) return setError(p);
    const r = await run(() => updateTimeout(realm, timeout.id, p.body), {
      quiet: true,
      success: t("timeouts.saved", "Timeout saved"),
      intent,
    });
    if (!r.ok) setError({ field: r.field, message: r.message });
    else setEnd("keep");
  }

  const badge = timeout ? (STATUS_BADGE[timeout.status] ?? STATUS_BADGE.ended) : null;
  let title = t("timeouts.timeout", "Timeout");
  if (mode === "create") title = t("timeouts.new_title", "Suspend for a while");
  else if (timeout) title = t("timeouts.title_of", "Timeout of {name}", { name: timeout.target.name });

  let footer: React.ReactNode;
  if (mode === "create") {
    footer = (
      <>
        <Button variant="destructive" onClick={create} loading={pending} disabled={locked || pending}>
          {pending
            ? t("timeouts.suspending", "Suspending…")
            : draft.startLater
              ? t("timeouts.schedule", "Schedule")
              : t("timeouts.suspend_now", "Suspend now")}
        </Button>
        <Button variant="secondary" onClick={close}>
          {t("common.cancel", "Cancel")}
        </Button>
      </>
    );
  } else if (current && writable && timeout) {
    footer = (
      <>
        <Button onClick={save} loading={pending} disabled={locked || pending}>
          {pending ? t("common.saving", "Saving…") : t("common.save", "Save")}
        </Button>
        <Button variant="secondary" onClick={close}>
          {t("common.cancel", "Cancel")}
        </Button>
        {!locked && (
          <span className="ml-auto">
            <LiftButton realm={realm} timeout={timeout} size="sm" onDone={close} />
          </span>
        )}
      </>
    );
  } else {
    footer = (
      <Button variant="secondary" onClick={close}>
        {t("common.close", "Close")}
      </Button>
    );
  }

  return (
    <Drawer
      open={mode === "create" || (mode === "edit" && !!timeout)}
      onClose={close}
      title={title}
      description={
        mode === "create" ? (
          t(
            "timeouts.new_description",
            "No sign-in and no token for the target until the end. The reason stays in the audit log.",
          )
        ) : timeout && badge ? (
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone={badge.tone}>{tm(badge.label)}</Badge>
            <Badge tone="neutral">{tm(TARGET_LABELS[timeout.target_type])}</Badge>
            <span>{t("timeouts.created_by", "Created by {who}", { who: timeout.created_by })}</span>
          </span>
        ) : undefined
      }
      footer={footer}
    >
      {(mode === "create" || current) && banner}
      {error && !FIELDS.includes(error.field ?? "") && <Banner tone="danger">{error.message}</Banner>}

      {mode === "create" && (
        <>
          <fieldset disabled={locked} className="space-y-5">
            <Field label={t("timeouts.field.suspend", "Suspend")} error={err("target_type")}>
              <Segmented
                label={t("timeouts.field.target_type", "Target type")}
                value={draft.targetType}
                disabled={locked}
                onChange={(v) => setDraft((d) => ({ ...d, targetType: v, targetId: "", targetName: "" }))}
                options={[
                  { value: "user", label: t("timeouts.field.a_user", "A user") },
                  { value: "group", label: t("timeouts.field.a_group", "A group") },
                  { value: "client", label: t("timeouts.field.an_application", "An application") },
                ]}
              />
            </Field>
            <TargetPicker
              key={draft.targetType}
              realm={realm}
              type={draft.targetType}
              selected={draft.targetId ? { id: draft.targetId, name: draft.targetName } : null}
              onSelect={(o) => setDraft((d) => ({ ...d, targetId: o?.id ?? "", targetName: o?.name ?? "" }))}
              disabled={locked}
              error={err("target_id")}
            />
            <Field label={t("timeouts.field.starts", "Starts")} error={err("starts_at")}>
              <Segmented
                label={t("timeouts.field.starts", "Starts")}
                value={draft.startLater ? "later" : "now"}
                disabled={locked}
                onChange={(v) => set("startLater", v === "later")}
                options={[
                  { value: "now", label: t("timeouts.field.now", "Now") },
                  { value: "later", label: t("timeouts.field.later", "Later") },
                ]}
              />
              {draft.startLater && (
                <Input
                  type="datetime-local"
                  aria-label={t("timeouts.field.start_at", "Start date and time")}
                  className="mt-2 w-60"
                  min={now}
                  value={draft.startAt}
                  onChange={(e) => set("startAt", e.target.value)}
                />
              )}
            </Field>
            <Field label={t("timeouts.field.for", "For")} error={err("ends_at")}>
              <Segmented<EndChoice>
                label={t("timeouts.field.duration", "Duration")}
                value={draft.end}
                disabled={locked}
                onChange={(v) => set("end", v)}
                options={END_CHOICES.map((c) => ({ value: c.value, label: tm(c.label) }))}
              />
              {draft.end === "date" && (
                <Input
                  type="datetime-local"
                  aria-label={t("timeouts.field.end_at", "End date and time")}
                  className="mt-2 w-60"
                  min={draft.startLater && draft.startAt ? draft.startAt : now}
                  value={draft.endAt}
                  onChange={(e) => set("endAt", e.target.value)}
                />
              )}
            </Field>
            <Field
              label={t("columns.reason", "Reason")}
              htmlFor="t-reason"
              hint={t(
                "timeouts.field.reason_hint",
                "For the administrators and the audit log. The user never sees it.",
              )}
              error={err("reason")}
            >
              <Textarea
                id="t-reason"
                rows={3}
                maxLength={500}
                value={draft.reason}
                onChange={(e) => set("reason", e.target.value)}
                placeholder={t(
                  "timeouts.field.reason_placeholder",
                  "Suspicious sign-ins under investigation (ticket SEC-142)",
                )}
              />
            </Field>
          </fieldset>
          {draft.targetId && (
            <Banner tone="warning">
              <p className="font-medium">{timeoutSummary(draft, fmt, undefined, tr)}</p>
              <p className="mt-1">{signOutNote(draft.targetType, draft.startLater, tr)}</p>
            </Banner>
          )}
        </>
      )}

      {mode === "edit" && timeout && (
        <>
          <dl className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 text-[13px]">
            <dt className="text-text-muted">{t("columns.target", "Target")}</dt>
            <dd className="font-medium">{timeout.target.name}</dd>
            <dt className="text-text-muted">{t("columns.start", "Start")}</dt>
            <dd>{formatDateTime(timeout.starts_at, locale)}</dd>
            <dt className="text-text-muted">{t("columns.end", "End")}</dt>
            <dd>
              {timeout.ends_at
                ? formatDateTime(timeout.ends_at, locale)
                : t("timeouts.no_end_until_lifted", "No end (until lifted)")}
            </dd>
            {timeout.lifted_at && (
              <>
                <dt className="text-text-muted">{t("timeouts.status.lifted", "Lifted")}</dt>
                <dd>
                  {t("timeouts.lifted_by", "{when} by {who}", {
                    when: formatDateTime(timeout.lifted_at, locale),
                    who: timeout.lifted_by ?? "",
                  })}
                </dd>
              </>
            )}
            <dt className="text-text-muted">{t("timeouts.signed_out", "Signed out")}</dt>
            <dd>
              {timeout.enforced_at
                ? formatDateTime(timeout.enforced_at, locale)
                : timeout.status === "scheduled"
                  ? t("timeouts.when_it_starts", "When it starts")
                  : timeout.status === "active"
                    ? t("timeouts.in_progress", "In progress")
                    : "—"}
            </dd>
            <dt className="text-text-muted">{t("columns.created", "Created")}</dt>
            <dd>{formatDateTime(timeout.created_at, locale)}</dd>
          </dl>
          {current ? (
            <fieldset disabled={locked} className="space-y-5 border-t border-border pt-5">
              <Field label={t("columns.end", "End")} error={err("ends_at")}>
                <Segmented<EditEnd>
                  label={t("columns.end", "End")}
                  value={end}
                  disabled={locked}
                  onChange={setEnd}
                  options={[
                    { value: "keep", label: t("timeouts.end.keep", "Keep") },
                    { value: "date", label: t("timeouts.end.another", "Another date") },
                    { value: "none", label: t("timeouts.end.none", "No end") },
                  ]}
                />
                {end === "date" && (
                  <Input
                    type="datetime-local"
                    aria-label={t("timeouts.field.new_end_at", "New end date and time")}
                    className="mt-2 w-60"
                    min={now}
                    value={endAt}
                    onChange={(e) => setEndAt(e.target.value)}
                  />
                )}
              </Field>
              <Field label={t("columns.reason", "Reason")} htmlFor="t-edit-reason" error={err("reason")}>
                <Textarea
                  id="t-edit-reason"
                  rows={3}
                  maxLength={500}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </Field>
              <p className="text-[12px] text-text-muted">
                {t(
                  "timeouts.start_fixed",
                  "The start cannot change: to move a scheduled timeout, cancel it and create another one.",
                )}
              </p>
            </fieldset>
          ) : (
            <section className="space-y-1 border-t border-border pt-5">
              <h3 className="text-[13px] font-semibold text-text-secondary">{t("columns.reason", "Reason")}</h3>
              <p className="text-[13px] whitespace-pre-wrap">{timeout.reason}</p>
            </section>
          )}
        </>
      )}
    </Drawer>
  );
}

/**
 * Search box for the target. The search runs as the admin types (a quarter
 * of a second after the last key) or focuses the box: never in an effect,
 * so nothing runs while the drawer is idle. A newer search wins over an
 * older answer.
 */
function TargetPicker({
  realm,
  type,
  selected,
  onSelect,
  disabled,
  error,
}: {
  realm: string;
  type: TimeoutTargetType;
  selected: { id: string; name: string } | null;
  onSelect: (o: TargetOption | null) => void;
  disabled: boolean;
  error?: string;
}) {
  const [q, setQ] = useState("");
  const [options, setOptions] = useState<TargetOption[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const seq = useRef(0);
  const { t, tm } = useT();
  const words =
    type === "user"
      ? {
          search: t("timeouts.picker.search_user", "Search a user"),
          matching: t("timeouts.picker.matching_user", "Matching users"),
          none: t("timeouts.picker.none_user", "No user matches."),
        }
      : type === "group"
        ? {
            search: t("timeouts.picker.search_group", "Search a group"),
            matching: t("timeouts.picker.matching_group", "Matching groups"),
            none: t("timeouts.picker.none_group", "No group matches."),
          }
        : {
            search: t("timeouts.picker.search_client", "Search an application"),
            matching: t("timeouts.picker.matching_client", "Matching applications"),
            none: t("timeouts.picker.none_client", "No application matches."),
          };

  function search(value: string, delay: number) {
    if (timer.current) clearTimeout(timer.current);
    const n = ++seq.current;
    timer.current = setTimeout(async () => {
      setSearching(true);
      const r = await searchTimeoutTargets(realm, type, value);
      if (n !== seq.current) return; // the admin typed since: a newer search is on its way
      setSearching(false);
      setFailed(r.ok ? null : r.message);
      setOptions(r.ok ? r.data : []);
    }, delay);
  }

  if (selected) {
    return (
      <Field label={tm(TARGET_LABELS[type])} error={error}>
        <div className="flex items-center justify-between rounded-lg border border-border px-3 py-2">
          <span className="flex items-center gap-2 text-[14px]">
            <Badge tone="neutral">{tm(TARGET_LABELS[type])}</Badge>
            <span className="font-medium">{selected.name}</span>
          </span>
          {!disabled && (
            <Button
              size="xs"
              variant="ghost"
              onClick={() => {
                onSelect(null);
                setQ("");
                setOptions(null);
              }}
            >
              <X className="size-3.5" />
              {t("timeouts.picker.change", "Change")}
            </Button>
          )}
        </div>
      </Field>
    );
  }

  return (
    <Field
      label={tm(TARGET_LABELS[type])}
      htmlFor="t-target"
      error={error ?? failed ?? undefined}
      hint={type === "user" ? t("timeouts.picker.user_hint", "Username, name or e-mail.") : undefined}
    >
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-text-muted" />
        <Input
          id="t-target"
          className="pl-9"
          autoComplete="off"
          value={q}
          placeholder={words.search}
          onFocus={() => options === null && search(q, 0)}
          onChange={(e) => {
            setQ(e.target.value);
            search(e.target.value, 250);
          }}
        />
      </div>
      {options !== null && (
        <ul
          aria-label={words.matching}
          aria-busy={searching}
          className="mt-2 max-h-64 divide-y divide-border overflow-y-auto rounded-lg border border-border"
        >
          {options.length === 0 && !searching && (
            <li className="px-3 py-2 text-[13px] text-text-muted">{words.none}</li>
          )}
          {options.map((o) => (
            <li key={o.id}>
              <button
                type="button"
                className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-[13px] hover:bg-surface-alt focus-visible:bg-surface-alt focus-visible:outline-none"
                onClick={() => onSelect(o)}
              >
                <span className="font-medium">{o.name}</span>
                <span className="truncate text-text-muted">{o.hint}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Field>
  );
}
