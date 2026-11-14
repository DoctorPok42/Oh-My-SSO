"use client";

import { KeyRound, Laptop, LogOut, Mail, Plus, ShieldOff, Smartphone, Trash2, Unlock, X } from "lucide-react";
import { NavLink } from "@/components/console/nav-link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { SecretOnceDialog } from "@/components/console/secret-once";
import { useStepUp } from "@/components/console/step-up";
import { StatusBadge } from "@/components/console/status-badge";
import { SuspendLink } from "@/components/console/suspend-link";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CheckboxField } from "@/components/ui/checkbox";
import { Chips, ChipSelect } from "@/components/ui/chip-select";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { useT } from "@/i18n/client";
import { formatDate, formatDateTime, formatRelative } from "@/lib/format";
import { EMAIL_KIND_LABELS, MFA_METHOD_LABELS } from "@/lib/labels";
import type { Access, OutboxEmail, UserDetail } from "@/lib/types";
import { profilePatch, sameSet } from "@/lib/user-form";
import {
  deleteUser,
  inviteUser,
  resendActivation,
  resendEmail,
  resetUserMfa,
  revokeTrustedDevice,
  revokeTrustedDevices,
  revokeUserSessions,
  sendEmailVerification,
  setUserGroups,
  setUserRoles,
  unlockUser,
  updateUser,
} from "./actions";

type Once = { title: string; description: string; items: { label: string; value: string }[] } | null;

export function InviteUserButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  const { t } = useT();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      {t("users.invite", "Invite user")}
    </Button>
  );
}

export function UserRowActions({ id }: { id: string }) {
  const { openEdit } = useDrawerUrl();
  const { t } = useT();
  return (
    <Button variant="secondary" size="xs" onClick={() => openEdit(id)}>
      {t("common.open", "Open")}
    </Button>
  );
}

type Draft = {
  username: string;
  email: string;
  name: string;
  status: string;
  extra: { key: string; value: string }[];
  groupIds: string[];
  roleIds: string[];
  sendEmail: boolean;
};

function toDraft(u: UserDetail | null, emailEnabled: boolean): Draft {
  if (!u)
    return {
      username: "",
      email: "",
      name: "",
      status: "active",
      extra: [],
      groupIds: [],
      roleIds: [],
      sendEmail: emailEnabled,
    };
  const { name, ...rest } = u.profile ?? {};
  return {
    username: u.username,
    email: u.email,
    name: typeof name === "string" ? name : "",
    status: u.status,
    extra: Object.entries(rest).map(([key, value]) => ({ key, value: String(value ?? "") })),
    groupIds: u.groups.map((g) => g.id),
    roleIds: u.roles.map((r) => r.id),
    sendEmail: emailEnabled,
  };
}

export function UserDrawer({
  realm,
  mode,
  user,
  writable,
  roles,
  groups,
  readAccess,
  emailEnabled,
  canSuspend = false,
}: {
  realm: string;
  mode: "create" | "edit" | null;
  user: UserDetail | null;
  writable: boolean;
  roles: Access[];
  groups: Access[];
  readAccess: boolean;
  emailEnabled: boolean;
  /** timeout:write: the footer offers "Suspend…" (Timeouts page). */
  canSuspend?: boolean;
}) {
  const { close, openEdit } = useDrawerUrl();
  const { run, pending } = useAction();
  const tr = useT();
  const { t, locale } = tr;
  const pathname = usePathname();
  const [draft, setDraft] = useState<Draft>(() => toDraft(user, emailEnabled));
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [once, setOnce] = useState<Once>(null);
  const key = mode === "create" ? "new" : (user?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(toDraft(user, emailEnabled));
    setError(null);
  }
  const { locked, banner } = useEditLock({
    canWrite: writable,
    intent: mode === "create" ? "new=1" : user ? `edit=${user.id}` : undefined,
  });
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const err = (f: string) => (error?.field === f ? error.message : undefined);
  const realmBase = pathname.split("/").slice(0, 3).join("/");

  async function save() {
    setError(null);
    if (mode === "create") {
      const profile: Record<string, string> = {};
      if (draft.name.trim()) profile.name = draft.name.trim();
      for (const { key, value } of draft.extra) if (key.trim()) profile[key.trim()] = value;
      const r = await run(
        () =>
          inviteUser(realm, {
            username: draft.username.trim(),
            email: draft.email.trim(),
            profile,
            group_ids: draft.groupIds,
            role_ids: draft.roleIds,
            send_email: draft.sendEmail,
          }),
        { quiet: true, intent: "new=1" },
      );
      if (!r.ok) return setError({ field: r.field, message: r.message });
      if (!r.data.activation_url) {
        toast.success(t("users.invited_email", "Invitation e-mailed to {email}", { email: r.data.user.email }));
      } else {
        setOnce({
          title: t("users.activation.send", "Send this activation link"),
          description: t(
            "users.activation.chooses",
            "{email} chooses a password with it (single use, expires {when}).",
            { email: r.data.user.email, when: formatDateTime(r.data.expires_at, locale) },
          ),
          items: [{ label: t("users.activation.link", "Activation link"), value: r.data.activation_url }],
        });
      }
      openEdit(r.data.user.id);
      return;
    }
    if (!user) return;
    // Three endpoints; only what changed is sent.
    const patch: Parameters<typeof updateUser>[2] = {};
    if (draft.username.trim() !== user.username) patch.username = draft.username.trim();
    if (draft.email.trim() !== user.email) patch.email = draft.email.trim();
    if (draft.status !== user.status) patch.status = draft.status;
    const profile = profilePatch(user.profile ?? {}, draft.name, draft.extra);
    if (Object.keys(profile).length) patch.profile = profile;
    const steps: (() => ReturnType<typeof updateUser>)[] = [];
    if (Object.keys(patch).length) steps.push(() => updateUser(realm, user.id, patch));
    if (
      readAccess &&
      !sameSet(
        draft.groupIds,
        user.groups.map((g) => g.id),
      )
    )
      steps.push(() => setUserGroups(realm, user.id, draft.groupIds));
    if (
      readAccess &&
      !sameSet(
        draft.roleIds,
        user.roles.map((r) => r.id),
      )
    )
      steps.push(() => setUserRoles(realm, user.id, draft.roleIds));
    if (steps.length === 0) return close();
    for (const [i, step] of steps.entries()) {
      const r = await run(step, {
        quiet: true,
        intent: `edit=${user.id}`,
        success: i === steps.length - 1 ? t("users.saved", "User saved") : undefined,
      });
      if (!r.ok) return setError({ field: r.field, message: r.message });
    }
  }

  return (
    <>
      <Drawer
        open={mode !== null}
        onClose={close}
        title={
          mode === "create" ? t("users.invite", "Invite user") : user?.name || user?.username || t("users.user", "User")
        }
        description={
          mode === "create"
            ? t(
                "users.invite_description",
                "The account is created without a password: the user chooses it with an activation link.",
              )
            : user && (
                <span className="flex flex-wrap items-center gap-2">
                  {!user.has_password ? <StatusBadge status="invited" /> : <StatusBadge status={user.status} />}
                  {user.locked && <StatusBadge status="locked" />}
                  <span>
                    {t("users.created_last_signin", "Created {created} · last sign-in {last}", {
                      created: formatDate(user.created_at, locale),
                      last: formatRelative(user.last_login_at, undefined, tr),
                    })}
                  </span>
                </span>
              )
        }
        footer={
          <>
            <Button onClick={save} loading={pending} disabled={locked || pending}>
              {pending
                ? t("common.saving", "Saving…")
                : mode === "create"
                  ? t("users.send_invitation", "Send invitation")
                  : t("common.save", "Save")}
            </Button>
            <Button variant="secondary" onClick={close}>
              {t("common.cancel", "Cancel")}
            </Button>
            {mode === "edit" && user && canSuspend && (
              <SuspendLink className="ml-auto" realm={realm} type="user" id={user.id} name={user.username} />
            )}
          </>
        }
      >
        {banner}
        {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
        <fieldset disabled={locked} className="space-y-5">
          <Field label={t("columns.email", "Email")} htmlFor="u-email" error={err("email")}>
            <Input
              id="u-email"
              autoFocus={mode === "create"}
              type="email"
              autoComplete="off"
              value={draft.email}
              onChange={(e) => set("email", e.target.value)}
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label={t("users.field.display_name", "Display name")}
              htmlFor="u-name"
              optional
              error={err("profile")}
            >
              <Input
                id="u-name"
                value={draft.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="Alice Moreau"
              />
            </Field>
            <Field
              label={t("users.field.username", "Username")}
              htmlFor="u-username"
              optional={mode === "create"}
              hint={
                mode === "create"
                  ? t("users.field.username_hint", "Empty: the part of the e-mail before @.")
                  : undefined
              }
              error={err("username")}
            >
              <Input
                id="u-username"
                className="font-mono"
                value={draft.username}
                onChange={(e) => set("username", e.target.value)}
              />
            </Field>
          </div>
          {mode === "edit" && (
            <Field
              label={t("columns.status", "Status")}
              htmlFor="u-status"
              hint={t("users.field.status_hint", "A user who is not active is signed out everywhere at once.")}
              error={err("status")}
            >
              <NativeSelect id="u-status" value={draft.status} onChange={(e) => set("status", e.target.value)}>
                <option value="active">{t("status.active", "Active")}</option>
                <option value="suspended">{t("users.status.suspended", "Suspended (temporarily blocked)")}</option>
                <option value="inactive">{t("users.status.inactive", "Inactive (left, kept for the records)")}</option>
              </NativeSelect>
            </Field>
          )}

          <Field
            label={t("users.field.attributes", "Other attributes")}
            hint={t(
              "users.field.attributes_hint",
              "Free profile attributes (department, phone...), usable in claim mappers as profile.<key>.",
            )}
          >
            <div className="space-y-2">
              {draft.extra.map((row, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    aria-label={t("users.field.attribute", "Attribute")}
                    className="h-9 w-40 font-mono text-[13px]"
                    value={row.key}
                    onChange={(e) =>
                      set(
                        "extra",
                        draft.extra.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)),
                      )
                    }
                    placeholder="department"
                  />
                  <Input
                    aria-label={t("users.field.value", "Value")}
                    className="h-9"
                    value={row.value}
                    onChange={(e) =>
                      set(
                        "extra",
                        draft.extra.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)),
                      )
                    }
                  />
                  <button
                    type="button"
                    aria-label={t("users.field.remove_attribute", "Remove this attribute")}
                    onClick={() =>
                      set(
                        "extra",
                        draft.extra.filter((_, j) => j !== i),
                      )
                    }
                    className="rounded-sm p-1 text-text-muted hover:bg-surface-alt hover:text-danger"
                  >
                    <X className="size-4" />
                  </button>
                </div>
              ))}
              <Button
                size="xs"
                variant="secondary"
                onClick={() => set("extra", [...draft.extra, { key: "", value: "" }])}
              >
                <Plus className="size-3.5" />
                {t("users.field.add_attribute", "Add attribute")}
              </Button>
            </div>
          </Field>

          {readAccess ? (
            <>
              <Field
                label={t("columns.groups", "Groups")}
                hint={t(
                  "users.field.groups_hint",
                  "The recommended way to give access: auditable, shared by many users.",
                )}
              >
                <ChipSelect
                  label={t("columns.groups", "Groups")}
                  options={groups}
                  value={draft.groupIds}
                  onChange={(v) => set("groupIds", v)}
                  disabled={locked}
                  empty={t("clients.access.no_group", "No group in this realm.")}
                />
              </Field>
              <Field label={t("users.tab.roles", "Roles")}>
                <ChipSelect
                  label={t("users.tab.roles", "Roles")}
                  options={roles}
                  value={draft.roleIds}
                  onChange={(v) => set("roleIds", v)}
                  disabled={locked}
                  empty={t("clients.access.no_role", "No role in this realm.")}
                />
                {draft.roleIds.length > 0 && (
                  <p className="mt-1.5 text-[12px] text-warning">
                    {t("users.field.roles_warning", "Roles given one by one are less auditable than a group at scale.")}
                  </p>
                )}
              </Field>
            </>
          ) : (
            <p className="text-[12px] text-text-muted">
              {t("users.access_hidden", "Groups and roles are hidden: you may not read them.")}
            </p>
          )}

          {mode === "create" && (
            <CheckboxField
              id="u-send"
              label={t("users.send_email", "E-mail the activation link")}
              hint={
                emailEnabled
                  ? t("users.send_email_hint", "Otherwise the link is shown here, once, for you to send.")
                  : t(
                      "users.no_email_hint",
                      "E-mail is not configured on the server: the link will be shown here, once.",
                    )
              }
              checked={draft.sendEmail && emailEnabled}
              disabled={!emailEnabled}
              onCheckedChange={(v) => set("sendEmail", v === true)}
            />
          )}
        </fieldset>

        {mode === "edit" && user && (
          <UserDetails
            realm={realm}
            user={user}
            locked={locked}
            emailEnabled={emailEnabled}
            realmBase={realmBase}
            onOnce={setOnce}
            onDeleted={close}
          />
        )}
      </Drawer>
      <SecretOnceDialog
        open={!!once}
        title={once?.title ?? ""}
        description={once?.description}
        items={once?.items ?? []}
        onDone={() => setOnce(null)}
      />
    </>
  );
}

function UserDetails({
  realm,
  user,
  locked,
  emailEnabled,
  realmBase,
  onOnce,
  onDeleted,
}: {
  realm: string;
  user: UserDetail;
  locked: boolean;
  emailEnabled: boolean;
  realmBase: string;
  onOnce: (o: Once) => void;
  onDeleted: () => void;
}) {
  const [resetOpen, setResetOpen] = useState(false);
  const [reason, setReason] = useState("");
  const { run, pending } = useAction();
  const stepUp = useStepUp();
  const tr = useT();
  const { t, tm, tn, locale } = tr;
  return (
    <div className="space-y-6 border-t border-border pt-5">
      <section>
        <h3 className="mb-2 text-[13px] font-semibold text-text-secondary">
          {t("users.effective", "Effective rights")}{" "}
          <span className="font-normal text-text-muted">
            {t("users.effective_hint", "(read-only: union of roles and groups)")}
          </span>
        </h3>
        <Chips
          items={user.effective.permissions.map((p) => ({
            id: p.id,
            name: p.name,
            title: t("users.from_sources", "from {sources}", { sources: p.sources.join(", ") }),
          }))}
          empty={t("users.no_permission_short", "No permission.")}
        />
        {user.effective.client_scopes.length > 0 && (
          <div className="mt-2">
            <Chips
              items={user.effective.client_scopes.map((s) => ({
                id: s.id,
                name: t("users.scope_chip", "scope: {name}", { name: s.name }),
                title: t("users.from_sources", "from {sources}", { sources: s.sources.join(", ") }),
              }))}
            />
          </div>
        )}
      </section>

      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-text-secondary">
            {t("users.mfa_methods", "MFA methods")}{" "}
            <span className="font-normal text-text-muted">{t("users.read_only", "(read-only)")}</span>
          </h3>
          {user.factors.length > 0 && !locked && (
            <Button size="xs" variant="danger" onClick={() => stepUp.ensure(() => setResetOpen(true))}>
              <ShieldOff className="size-3.5" />
              {t("users.mfa_reset", "Reset MFA")}
            </Button>
          )}
        </div>
        {user.factors.length === 0 ? (
          <p className="text-[13px] text-text-muted">{t("users.no_factor", "No second factor.")}</p>
        ) : (
          <ul className="space-y-2">
            {user.factors.map((f) => (
              <li key={f.id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                {f.type === "totp" ? (
                  <Smartphone className="mt-0.5 size-4 text-text-muted" />
                ) : (
                  <KeyRound className="mt-0.5 size-4 text-text-muted" />
                )}
                <div className="min-w-0">
                  <p className="text-[13px] font-medium">
                    {MFA_METHOD_LABELS[f.type] ? tm(MFA_METHOD_LABELS[f.type]!) : f.type} —{" "}
                    {f.name || t("users.unnamed", "unnamed")}
                  </p>
                  <p className="text-[12px] text-text-muted">
                    {t("users.factor_dates", "Added {added} · last used {used}", {
                      added: formatDate(f.created_at, locale),
                      used: formatRelative(f.last_used_at, undefined, tr),
                    })}
                  </p>
                </div>
              </li>
            ))}
            {user.backup_codes_left > 0 && (
              <li className="text-[12px] text-text-muted">
                {tn(
                  "users.codes_left",
                  user.backup_codes_left,
                  "{count} backup code left.",
                  "{count} backup codes left.",
                )}
              </li>
            )}
          </ul>
        )}
      </section>

      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-text-secondary">
            {t("users.trusted_devices", "Trusted devices")}{" "}
            <span className="font-normal text-text-muted">
              {t("users.trusted_devices_hint", '("Don\'t ask again on this device")')}
            </span>
          </h3>
          {user.trusted_devices.length > 1 && (
            <ConfirmAction
              variant="secondary"
              size="xs"
              disabled={locked}
              trigger={t("users.revoke_all", "Revoke all")}
              title={t("users.revoke_devices_title", "Revoke the trusted devices of {user}?", { user: user.username })}
              description={t(
                "users.revoke_devices_text",
                "The next sign-in on each of them asks for the second factor again.",
              )}
              confirmLabel={t("users.revoke_all", "Revoke all")}
              success={t("users.devices_revoked", "Trusted devices revoked")}
              action={() => revokeTrustedDevices(realm, user.id)}
            />
          )}
        </div>
        {user.trusted_devices.length === 0 ? (
          <p className="text-[13px] text-text-muted">
            {t("users.no_trusted_device", "No trusted device: every sign-in asks for the second factor.")}
          </p>
        ) : (
          <ul className="space-y-2">
            {user.trusted_devices.map((d) => (
              <li key={d.id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Laptop className="mt-0.5 size-4 text-text-muted" />
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] font-medium" title={d.user_agent}>
                    {d.device || t("users.unknown_device", "Unknown device")}
                    {d.ip_address && <span className="ml-2 font-mono text-[12px] text-text-muted">{d.ip_address}</span>}
                  </p>
                  <p className="text-[12px] text-text-muted">
                    {t("users.device_dates", "Trusted {since} · last used {used} · until {until}", {
                      since: formatDate(d.created_at, locale),
                      used: formatRelative(d.last_used_at, undefined, tr),
                      until: formatDate(d.expires_at, locale),
                    })}
                  </p>
                </div>
                <ConfirmAction
                  variant="secondary"
                  size="xs"
                  disabled={locked}
                  trigger={t("sessions.revoke", "Revoke")}
                  title={t("users.revoke_device_title", "Revoke this trusted device?")}
                  description={t(
                    "users.revoke_device_text",
                    "The next sign-in on it asks for the second factor again.",
                  )}
                  confirmLabel={t("sessions.revoke", "Revoke")}
                  success={t("users.device_revoked", "Trusted device revoked")}
                  action={() => revokeTrustedDevice(realm, user.id, d.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      <EmailSection realm={realm} user={user} locked={locked} emailEnabled={emailEnabled} />

      <section className="space-y-2">
        <h3 className="text-[13px] font-semibold text-text-secondary">{t("users.account", "Account")}</h3>
        <div className="flex flex-wrap gap-2">
          {user.locked && (
            <ConfirmAction
              variant="secondary"
              size="sm"
              disabled={locked}
              trigger={
                <>
                  <Unlock className="size-3.5" />
                  {t("users.unlock", "Unlock")}
                </>
              }
              title={t("users.unlock_title", "Unlock this account?")}
              description={
                user.locked_until
                  ? tn(
                      "users.unlock_text_until",
                      user.failed_logins,
                      "Clears the {count} failed sign-in that locked it until {until}.",
                      "Clears the {count} failed sign-ins that locked it until {until}.",
                      { until: formatDateTime(user.locked_until, locale) },
                    )
                  : tn(
                      "users.unlock_text",
                      user.failed_logins,
                      "Clears the {count} failed sign-in that locked it.",
                      "Clears the {count} failed sign-ins that locked it.",
                    )
              }
              confirmLabel={t("users.unlock", "Unlock")}
              confirmVariant="primary"
              success={t("users.unlocked", "Account unlocked")}
              action={() => unlockUser(realm, user.id)}
            />
          )}
          {!user.has_password && (
            <ConfirmAction
              variant="secondary"
              size="sm"
              disabled={locked}
              trigger={t("users.activation.new", "New activation link")}
              title={t("users.activation.new_title", "Issue a new activation link?")}
              description={
                emailEnabled
                  ? t("users.activation.new_email", "It is e-mailed to the user; the previous link stops working.")
                  : t("users.activation.new_shown", "It will be shown once; the previous link stops working.")
              }
              confirmLabel={t("users.activation.issue", "Issue link")}
              confirmVariant="primary"
              action={() => resendActivation(realm, user.id, emailEnabled)}
              onDone={(r) =>
                r.activation_url
                  ? onOnce({
                      title: t("users.activation.send", "Send this activation link"),
                      description: t("users.activation.single_use", "Single use, expires {when}.", {
                        when: formatDateTime(r.expires_at, locale),
                      }),
                      items: [{ label: t("users.activation.link", "Activation link"), value: r.activation_url }],
                    })
                  : undefined
              }
              success={emailEnabled ? t("users.activation.emailed", "Activation link e-mailed") : undefined}
            />
          )}
          <ConfirmAction
            variant="secondary"
            size="sm"
            disabled={locked}
            trigger={
              <>
                <LogOut className="size-3.5" />
                {t("users.sign_out_everywhere", "Sign out everywhere")}
              </>
            }
            title={t("users.sign_out_title", "Sign {user} out everywhere?", { user: user.username })}
            description={t("users.sign_out_text", "Every session and token of this user is revoked now.")}
            confirmLabel={t("users.sign_out_everywhere", "Sign out everywhere")}
            success={t("users.sessions_revoked", "All sessions revoked")}
            action={() => revokeUserSessions(realm, user.id)}
          />
        </div>
        <p className="flex gap-4 text-[13px]">
          <NavLink
            href={`${realmBase}/sessions?user=${encodeURIComponent(user.id)}`}
            className="text-accent hover:underline"
          >
            {t("users.view_sessions", "View sessions")}
          </NavLink>
          <NavLink
            href={`${realmBase}/audit?user=${encodeURIComponent(user.id)}`}
            className="text-accent hover:underline"
          >
            {t("users.view_audit", "View audit trail")}
          </NavLink>
        </p>
      </section>

      <section className="rounded-lg border border-danger-soft p-4">
        <h3 className="text-[13px] font-semibold text-danger">{t("users.delete.section", "Delete this user")}</h3>
        <p className="mt-1 mb-3 text-[12px] text-text-muted">
          {t(
            "users.delete.hint",
            'The account is removed and signed out everywhere. Prefer "Inactive" to keep it for the records.',
          )}
        </p>
        <ConfirmAction
          size="sm"
          disabled={locked}
          trigger={
            <>
              <Trash2 className="size-3.5" />
              {t("users.delete.confirm", "Delete user")}
            </>
          }
          title={t("clients.delete.title", "Delete {name}?", { name: user.username })}
          description={t("common.cannot_undo", "This cannot be undone.")}
          confirmLabel={t("users.delete.confirm", "Delete user")}
          success={t("users.delete.done", "User deleted")}
          action={() => deleteUser(realm, user.id)}
          onDone={onDeleted}
        />
      </section>

      <Dialog open={resetOpen} onOpenChange={setResetOpen}>
        <DialogContent>
          <DialogTitle>{t("users.mfa_reset_title", "Reset the MFA of {user}?", { user: user.username })}</DialogTitle>
          <DialogDescription>
            {t(
              "users.mfa_reset_text",
              "Every factor and backup code is deleted and the user is signed out everywhere. They set up a new factor at the next sign-in. Check who asked first: this is a classic social-engineering target.",
            )}
          </DialogDescription>
          <Field
            label={t("users.mfa_reset_reason", "Reason (kept in the audit log)")}
            htmlFor="mfa-reason"
            className="mt-4"
          >
            <Textarea
              id="mfa-reason"
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t("users.mfa_reset_placeholder", "Lost phone, identity checked by video call")}
            />
          </Field>
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setResetOpen(false)}>
              {t("common.cancel", "Cancel")}
            </Button>
            <Button
              variant="destructive"
              loading={pending}
              disabled={pending || reason.trim().length < 3}
              onClick={async () => {
                const r = await run(() => resetUserMfa(realm, user.id, reason.trim()), {
                  success: t("users.mfa_reset_done", "MFA reset"),
                });
                if (r.ok) {
                  setResetOpen(false);
                  setReason("");
                }
              }}
            >
              {t("users.mfa_reset", "Reset MFA")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/** The address (verified or not) and the latest e-mails of the account, with what became of them. */
function EmailSection({
  realm,
  user,
  locked,
  emailEnabled,
}: {
  realm: string;
  user: UserDetail;
  locked: boolean;
  emailEnabled: boolean;
}) {
  const tr = useT();
  const { t, tm, locale } = tr;
  const markLabel = user.email_verified
    ? t("users.verify_unmark", "Mark as not verified")
    : t("users.verify_mark", "Mark as verified");
  return (
    <section className="space-y-3">
      <h3 className="text-[13px] font-semibold text-text-secondary">{t("users.email_section", "E-mail")}</h3>
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        <Mail className="size-4 text-text-muted" />
        <span className="font-medium">{user.email}</span>
        {user.email_verified ? (
          <StatusBadge status="verified" />
        ) : (
          <StatusBadge status="unverified" label={t("users.email_unverified", "Not verified")} />
        )}
        {user.email_verified && user.email_verified_at && (
          <span className="text-[12px] text-text-muted">
            {t("users.email_verified_since", "since {when}", { when: formatDate(user.email_verified_at, locale) })}
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        {!user.email_verified && emailEnabled && user.status === "active" && (
          <ConfirmAction
            variant="secondary"
            size="sm"
            disabled={locked}
            trigger={t("users.verify_send", "Send a verification e-mail")}
            title={t("users.verify_send_title", "E-mail {user} a verification link?", { user: user.username })}
            description={t(
              "users.verify_send_text",
              "The link works for 24 hours. Opening it marks the address verified: applications then receive email_verified = true.",
            )}
            confirmLabel={t("users.verify_send_confirm", "Send")}
            confirmVariant="primary"
            success={t("users.verify_sent", "Verification e-mail sent")}
            action={() => sendEmailVerification(realm, user.id)}
          />
        )}
        <ConfirmAction
          variant="secondary"
          size="sm"
          disabled={locked}
          trigger={markLabel}
          title={
            user.email_verified
              ? t("users.verify_unmark_title", "Mark this address as not verified?")
              : t("users.verify_mark_title", "Mark this address as verified?")
          }
          description={
            user.email_verified
              ? t(
                  "users.verify_unmark_text",
                  "Applications receive email_verified = false until the user confirms the address again.",
                )
              : t(
                  "users.verify_mark_text",
                  "Only if you checked yourself that this address belongs to the user: applications rely on it (email_verified = true).",
                )
          }
          confirmLabel={markLabel}
          confirmVariant="primary"
          success={t("users.verify_marked", "Saved")}
          action={() => updateUser(realm, user.id, { email_verified: !user.email_verified })}
        />
      </div>

      {user.emails.length === 0 ? (
        <p className="text-[13px] text-text-muted">{t("users.no_email", "No e-mail sent to this account recently.")}</p>
      ) : (
        <ul className="space-y-2">
          {user.emails.map((e) => (
            <EmailRow
              key={e.id}
              realm={realm}
              userId={user.id}
              email={e}
              locked={locked}
              label={EMAIL_KIND_LABELS[e.kind] ? tm(EMAIL_KIND_LABELS[e.kind]!) : e.kind}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function EmailRow({
  realm,
  userId,
  email: e,
  locked,
  label,
}: {
  realm: string;
  userId: string;
  email: OutboxEmail;
  locked: boolean;
  label: string;
}) {
  const { t, tn, locale } = useT();
  let when = t("users.email_asked_at", "Asked {when}", { when: formatDateTime(e.created_at, locale) });
  if (e.status === "sent") {
    when = t("users.email_sent_at", "Sent {when}", { when: formatDateTime(e.sent_at ?? e.created_at, locale) });
  } else if (e.status === "pending" && e.next_attempt_at) {
    when = t("users.email_next_attempt", "Next attempt {when}, until {deadline}", {
      when: formatDateTime(e.next_attempt_at, locale),
      deadline: formatDateTime(e.deadline, locale),
    });
  }
  return (
    <li className="flex items-start gap-3 rounded-lg border border-border p-3">
      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
          {label}
          <StatusBadge status={e.status} />
          {e.attempts > 1 && (
            <span className="text-[12px] font-normal text-text-muted">
              {tn("users.email_attempts", e.attempts, "{count} attempt", "{count} attempts")}
            </span>
          )}
        </p>
        <p className="text-[12px] text-text-muted">{[e.recipient, when].filter(Boolean).join(" · ")}</p>
        {e.last_error && e.status !== "sent" && (
          <p className="mt-1 text-[12px] break-words text-text-muted">{e.last_error}</p>
        )}
      </div>
      {e.can_resend && (
        <ConfirmAction
          variant="secondary"
          size="xs"
          disabled={locked}
          trigger={
            e.status === "pending" ? t("users.email_retry_now", "Retry now") : t("users.email_resend", "Send again")
          }
          title={t("users.email_resend_title", "Send this e-mail again?")}
          description={t(
            "users.email_resend_text",
            "It leaves at once; if the mail server still fails, it is tried again for 24 hours (or until its link expires).",
          )}
          confirmLabel={t("users.email_resend", "Send again")}
          confirmVariant="primary"
          success={t("users.email_requeued", "E-mail queued")}
          action={() => resendEmail(realm, userId, e.id)}
        />
      )}
    </li>
  );
}
