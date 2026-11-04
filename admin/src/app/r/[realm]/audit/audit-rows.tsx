"use client";

import { ChevronRight, Mail } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { StatusBadge } from "@/components/console/status-badge";
import { Badge } from "@/components/ui/badge";
import { TableCell, TableRow } from "@/components/ui/table";
import { m, type Msg } from "@/i18n";
import { useT } from "@/i18n/client";
import { ACTOR_TYPE_LABELS, actionLabel, isNotification } from "@/lib/labels";
import type { AuditAction, AuditEntry } from "@/lib/types";
import { cn } from "@/lib/utils";

// Who did it, at a glance: a person (user, admin) or not (system, CLI,
// nobody signed in).
const ACTOR_TONES: Record<string, "info" | "accent" | "neutral" | "warning"> = {
  user: "info",
  admin: "accent",
  cli: "neutral",
  system: "neutral",
  anonymous: "warning",
};

export function ActorBadge({ type }: { type: string }) {
  const { tm } = useT();
  const label = ACTOR_TYPE_LABELS[type];
  return (
    <Badge tone={ACTOR_TONES[type] ?? "neutral"} title={tm(actorHint(type))}>
      {label ? tm(label) : type}
    </Badge>
  );
}

const ACTOR_HINTS: Record<string, Msg> = {
  user: m("audit.actor_hint.user", "Done by a user of the realm, on their own account"),
  admin: m("audit.actor_hint.admin", "Done by an administrator in the admin console"),
  cli: m("audit.actor_hint.cli", "Done by an operator on the command line"),
  anonymous: m("audit.actor_hint.anonymous", "Nobody was signed in (a failed sign-in, a reset request...)"),
  system: m("audit.actor_hint.system", "Done by the server itself (lockout, key retirer, e-mails...)"),
};

function actorHint(type: string): Msg {
  return ACTOR_HINTS[type] ?? ACTOR_HINTS.system!;
}

// One line per entry; a click shows its details: who did it, whom and what
// it is about, from where, and the JSON the server recorded.
export function AuditRows({
  items,
  times,
  actions,
}: {
  items: AuditEntry[];
  times: Record<string, string>;
  actions: AuditAction[];
}) {
  const [open, setOpen] = useState<string | null>(null);
  const tr = useT();
  const { t, tm } = tr;
  const labels = useMemo(() => new Map(actions.map((a) => [a.name, a.label])), [actions]);
  return (
    <>
      {items.map((a) => {
        const expanded = open === a.id;
        const target = targetName(a);
        return (
          <Fragment key={a.id}>
            <TableRow className="cursor-pointer" onClick={() => setOpen(expanded ? null : a.id)}>
              <TableCell className="font-mono text-[12px] whitespace-nowrap text-text-secondary">
                {times[a.id]}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-1.5 whitespace-nowrap">
                  <ActorBadge type={a.actor_type} />
                  {a.actor && (
                    <span className="max-w-[160px] truncate text-[12px]" title={a.actor.id}>
                      {a.actor.username || a.actor.id}
                    </span>
                  )}
                </div>
              </TableCell>
              <TableCell>
                <button
                  type="button"
                  aria-expanded={expanded}
                  className="inline-flex items-center gap-1.5 text-left"
                  onClick={(e) => {
                    e.stopPropagation();
                    setOpen(expanded ? null : a.id);
                  }}
                >
                  <ChevronRight
                    className={cn("size-3.5 text-text-muted transition-transform", expanded && "rotate-90")}
                  />
                  {isNotification(a.action) && (
                    <Mail className="size-3.5 text-text-muted" aria-label={t("dashboard.email", "e-mail")} />
                  )}
                  <span className="font-mono text-[12px]">{a.action}</span>
                </button>
                <p className="ml-5 text-[12px] text-text-muted">{actionLabel(a.action, labels, tr)}</p>
              </TableCell>
              <TableCell className="text-[12px] text-text-secondary">
                {target || a.resource_type ? (
                  <>
                    {target && <span className="block max-w-[180px] truncate">{target}</span>}
                    {a.resource_type && (
                      <span
                        className="block max-w-[180px] truncate font-mono text-[11px] text-text-muted"
                        title={a.resource_id}
                      >
                        {a.resource_type}
                        {a.resource_id && ` · ${a.resource_id}`}
                      </span>
                    )}
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="font-mono text-[12px] text-text-secondary">{a.ip_address || "—"}</TableCell>
              <TableCell>
                <div className="flex flex-wrap gap-1">
                  <StatusBadge status={a.status} />
                  {a.level !== "info" && a.level !== "debug" && <StatusBadge status={a.level} />}
                </div>
              </TableCell>
            </TableRow>
            {expanded && (
              <TableRow className="bg-surface-alt hover:bg-surface-alt!">
                <TableCell colSpan={6}>
                  <dl className="grid gap-x-6 gap-y-2 text-[12px] sm:grid-cols-[140px_1fr]">
                    <dt className="text-text-muted">{t("audit.entry_id", "Entry ID")}</dt>
                    <dd className="font-mono">{a.id}</dd>
                    <dt className="text-text-muted">{t("columns.actor", "Actor")}</dt>
                    <dd className="flex flex-wrap items-center gap-2">
                      <ActorBadge type={a.actor_type} />
                      {a.actor ? (
                        <span>
                          {a.actor.username || t("audit.deleted_account", "deleted account")}{" "}
                          <span className="font-mono text-text-muted">{a.actor.id}</span>
                        </span>
                      ) : (
                        <span className="text-text-muted">{tm(actorHint(a.actor_type))}</span>
                      )}
                    </dd>
                    <dt className="text-text-muted">{t("audit.target_user", "Target user")}</dt>
                    <dd>
                      {a.target ? (
                        <span>
                          {a.target.username || t("audit.deleted_account", "deleted account")}{" "}
                          <span className="font-mono text-text-muted">{a.target.id}</span>
                        </span>
                      ) : (
                        "—"
                      )}
                    </dd>
                    <dt className="text-text-muted">{t("audit.resource", "Resource")}</dt>
                    <dd>
                      {a.resource_type ? (
                        <span>
                          {a.resource_type} <span className="font-mono text-text-muted">{a.resource_id || "—"}</span>
                        </span>
                      ) : (
                        "—"
                      )}
                    </dd>
                    <dt className="text-text-muted">{t("columns.ip_address", "IP address")}</dt>
                    <dd className="font-mono">{a.ip_address || "—"}</dd>
                    <dt className="text-text-muted">{t("audit.user_agent", "User agent")}</dt>
                    <dd className="break-all">{a.user_agent || "—"}</dd>
                    <dt className="text-text-muted">{t("audit.details", "Details")}</dt>
                    <dd>
                      <pre className="overflow-x-auto rounded-md border border-border bg-surface p-3 font-mono text-[12px]">
                        {JSON.stringify(a.details, null, 2)}
                      </pre>
                    </dd>
                  </dl>
                </TableCell>
              </TableRow>
            )}
          </Fragment>
        );
      })}
    </>
  );
}

/** The target user's name; nothing when it is the actor themselves (it would say the same twice). */
function targetName(a: AuditEntry): string {
  if (!a.target) return "";
  if (a.actor && a.actor.id === a.target.id) return "";
  return a.target.username || a.target.id;
}
