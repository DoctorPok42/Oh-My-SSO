"use client";

import { KeyRound, Laptop, LogOut, Plus, ShieldOff, Smartphone, Trash2, Unlock, X } from "lucide-react";
import { NavLink } from "@/components/console/nav-link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { SecretOnceDialog } from "@/components/console/secret-once";
import { useStepUp } from "@/components/console/step-up";
import { StatusBadge } from "@/components/console/status-badge";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CheckboxField } from "@/components/ui/checkbox";
import { Chips, ChipSelect } from "@/components/ui/chip-select";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { formatDate, formatDateTime, formatRelative } from "@/lib/format";
import { MFA_METHOD_LABELS } from "@/lib/labels";
import type { Access, UserDetail } from "@/lib/types";
import { profilePatch, sameSet } from "@/lib/user-form";
import {
  deleteUser,
  inviteUser,
  resendActivation,
  resetUserMfa,
  revokeTrustedDevice,
  revokeTrustedDevices,
  revokeUserSessions,
  setUserGroups,
  setUserRoles,
  unlockUser,
  updateUser,
} from "./actions";

type Once = { title: string; description: string; items: { label: string; value: string }[] } | null;

export function InviteUserButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      Invite user
    </Button>
  );
}

export function UserRowActions({ id }: { id: string }) {
  const { openEdit } = useDrawerUrl();
  return (
    <Button variant="secondary" size="xs" onClick={() => openEdit(id)}>
      Open
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
}: {
  realm: string;
  mode: "create" | "edit" | null;
  user: UserDetail | null;
  writable: boolean;
  roles: Access[];
  groups: Access[];
  readAccess: boolean;
  emailEnabled: boolean;
}) {
  const { close, openEdit } = useDrawerUrl();
  const { run, pending } = useAction();
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
        toast.success(`Invitation e-mailed to ${r.data.user.email}`);
      } else {
        setOnce({
          title: "Send this activation link",
          description: `${r.data.user.email} chooses a password with it (single use, expires ${formatDateTime(r.data.expires_at)}).`,
          items: [{ label: "Activation link", value: r.data.activation_url }],
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
        success: i === steps.length - 1 ? "User saved" : undefined,
      });
      if (!r.ok) return setError({ field: r.field, message: r.message });
    }
  }

  return (
    <>
      <Drawer
        open={mode !== null}
        onClose={close}
        title={mode === "create" ? "Invite user" : user?.name || user?.username || "User"}
        description={
          mode === "create"
            ? "The account is created without a password: the user chooses it with an activation link."
            : user && (
                <span className="flex flex-wrap items-center gap-2">
                  {!user.has_password ? (
                    <StatusBadge status="invited" label="Invited" />
                  ) : (
                    <StatusBadge status={user.status} />
                  )}
                  {user.locked && <StatusBadge status="locked" label="Locked" />}
                  <span>
                    Created {formatDate(user.created_at)} · last sign-in {formatRelative(user.last_login_at)}
                  </span>
                </span>
              )
        }
        footer={
          <>
            <Button onClick={save} loading={pending} disabled={locked || pending}>
              {pending ? "Saving…" : mode === "create" ? "Send invitation" : "Save"}
            </Button>
            <Button variant="secondary" onClick={close}>
              Cancel
            </Button>
          </>
        }
      >
        {banner}
        {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
        <fieldset disabled={locked} className="space-y-5">
          <Field label="Email" htmlFor="u-email" error={err("email")}>
            <Input
              id="u-email"
              type="email"
              autoComplete="off"
              value={draft.email}
              onChange={(e) => set("email", e.target.value)}
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Display name" htmlFor="u-name" optional error={err("profile")}>
              <Input
                id="u-name"
                value={draft.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="Alice Moreau"
              />
            </Field>
            <Field
              label="Username"
              htmlFor="u-username"
              optional={mode === "create"}
              hint={mode === "create" ? "Empty: the part of the e-mail before @." : undefined}
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
              label="Status"
              htmlFor="u-status"
              hint="A user who is not active is signed out everywhere at once."
              error={err("status")}
            >
              <NativeSelect id="u-status" value={draft.status} onChange={(e) => set("status", e.target.value)}>
                <option value="active">Active</option>
                <option value="suspended">Suspended (temporarily blocked)</option>
                <option value="inactive">Inactive (left, kept for the records)</option>
              </NativeSelect>
            </Field>
          )}

          <Field
            label="Other attributes"
            hint="Free profile attributes (department, phone...), usable in claim mappers as profile.<key>."
          >
            <div className="space-y-2">
              {draft.extra.map((row, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    aria-label="Attribute"
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
                    aria-label="Value"
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
                    aria-label="Remove this attribute"
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
                Add attribute
              </Button>
            </div>
          </Field>

          {readAccess ? (
            <>
              <Field label="Groups" hint="The recommended way to give access: auditable, shared by many users.">
                <ChipSelect
                  label="Groups"
                  options={groups}
                  value={draft.groupIds}
                  onChange={(v) => set("groupIds", v)}
                  disabled={locked}
                  empty="No group in this realm."
                />
              </Field>
              <Field label="Roles">
                <ChipSelect
                  label="Roles"
                  options={roles}
                  value={draft.roleIds}
                  onChange={(v) => set("roleIds", v)}
                  disabled={locked}
                  empty="No role in this realm."
                />
                {draft.roleIds.length > 0 && (
                  <p className="mt-1.5 text-[12px] text-warning">
                    Roles given one by one are less auditable than a group at scale.
                  </p>
                )}
              </Field>
            </>
          ) : (
            <p className="text-[12px] text-text-muted">Groups and roles are hidden: you may not read them.</p>
          )}

          {mode === "create" && (
            <CheckboxField
              id="u-send"
              label="E-mail the activation link"
              hint={
                emailEnabled
                  ? "Otherwise the link is shown here, once, for you to send."
                  : "E-mail is not configured on the server: the link will be shown here, once."
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
  return (
    <div className="space-y-6 border-t border-border pt-5">
      <section>
        <h3 className="mb-2 text-[13px] font-semibold text-text-secondary">
          Effective rights <span className="font-normal text-text-muted">(read-only: union of roles and groups)</span>
        </h3>
        <Chips
          items={user.effective.permissions.map((p) => ({
            id: p.id,
            name: p.name,
            title: `from ${p.sources.join(", ")}`,
          }))}
          empty="No permission."
        />
        {user.effective.client_scopes.length > 0 && (
          <div className="mt-2">
            <Chips
              items={user.effective.client_scopes.map((s) => ({
                id: s.id,
                name: `scope: ${s.name}`,
                title: `from ${s.sources.join(", ")}`,
              }))}
            />
          </div>
        )}
      </section>

      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-text-secondary">
            MFA methods <span className="font-normal text-text-muted">(read-only)</span>
          </h3>
          {user.factors.length > 0 && !locked && (
            <Button size="xs" variant="danger" onClick={() => stepUp.ensure(() => setResetOpen(true))}>
              <ShieldOff className="size-3.5" />
              Reset MFA
            </Button>
          )}
        </div>
        {user.factors.length === 0 ? (
          <p className="text-[13px] text-text-muted">No second factor.</p>
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
                    {MFA_METHOD_LABELS[f.type] ?? f.type} — {f.name || "unnamed"}
                  </p>
                  <p className="text-[12px] text-text-muted">
                    Added {formatDate(f.created_at)} · last used {formatRelative(f.last_used_at)}
                  </p>
                </div>
              </li>
            ))}
            {user.backup_codes_left > 0 && (
              <li className="text-[12px] text-text-muted">{user.backup_codes_left} backup code(s) left.</li>
            )}
          </ul>
        )}
      </section>

      <section>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-text-secondary">
            Trusted devices{" "}
            <span className="font-normal text-text-muted">(&quot;Don&apos;t ask again on this device&quot;)</span>
          </h3>
          {user.trusted_devices.length > 1 && (
            <ConfirmAction
              variant="secondary"
              size="xs"
              disabled={locked}
              trigger="Revoke all"
              title={`Revoke the trusted devices of ${user.username}?`}
              description="The next sign-in on each of them asks for the second factor again."
              confirmLabel="Revoke all"
              success="Trusted devices revoked"
              action={() => revokeTrustedDevices(realm, user.id)}
            />
          )}
        </div>
        {user.trusted_devices.length === 0 ? (
          <p className="text-[13px] text-text-muted">No trusted device: every sign-in asks for the second factor.</p>
        ) : (
          <ul className="space-y-2">
            {user.trusted_devices.map((d) => (
              <li key={d.id} className="flex items-start gap-3 rounded-lg border border-border p-3">
                <Laptop className="mt-0.5 size-4 text-text-muted" />
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] font-medium" title={d.user_agent}>
                    {d.device || "Unknown device"}
                    {d.ip_address && <span className="ml-2 font-mono text-[12px] text-text-muted">{d.ip_address}</span>}
                  </p>
                  <p className="text-[12px] text-text-muted">
                    Trusted {formatDate(d.created_at)} · last used {formatRelative(d.last_used_at)} · until{" "}
                    {formatDate(d.expires_at)}
                  </p>
                </div>
                <ConfirmAction
                  variant="secondary"
                  size="xs"
                  disabled={locked}
                  trigger="Revoke"
                  title="Revoke this trusted device?"
                  description="The next sign-in on it asks for the second factor again."
                  confirmLabel="Revoke"
                  success="Trusted device revoked"
                  action={() => revokeTrustedDevice(realm, user.id, d.id)}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-2">
        <h3 className="text-[13px] font-semibold text-text-secondary">Account</h3>
        <div className="flex flex-wrap gap-2">
          {user.locked && (
            <ConfirmAction
              variant="secondary"
              size="sm"
              disabled={locked}
              trigger={
                <>
                  <Unlock className="size-3.5" />
                  Unlock
                </>
              }
              title="Unlock this account?"
              description={`Clears the ${user.failed_logins} failed sign-in(s) that locked it${user.locked_until ? ` until ${formatDateTime(user.locked_until)}` : ""}.`}
              confirmLabel="Unlock"
              confirmVariant="primary"
              success="Account unlocked"
              action={() => unlockUser(realm, user.id)}
            />
          )}
          {!user.has_password && (
            <ConfirmAction
              variant="secondary"
              size="sm"
              disabled={locked}
              trigger="New activation link"
              title="Issue a new activation link?"
              description={
                emailEnabled
                  ? "It is e-mailed to the user; the previous link stops working."
                  : "It will be shown once; the previous link stops working."
              }
              confirmLabel="Issue link"
              confirmVariant="primary"
              action={() => resendActivation(realm, user.id, emailEnabled)}
              onDone={(r) =>
                r.activation_url
                  ? onOnce({
                      title: "Send this activation link",
                      description: `Single use, expires ${formatDateTime(r.expires_at)}.`,
                      items: [{ label: "Activation link", value: r.activation_url }],
                    })
                  : undefined
              }
              success={emailEnabled ? "Activation link e-mailed" : undefined}
            />
          )}
          <ConfirmAction
            variant="secondary"
            size="sm"
            disabled={locked}
            trigger={
              <>
                <LogOut className="size-3.5" />
                Sign out everywhere
              </>
            }
            title={`Sign ${user.username} out everywhere?`}
            description="Every session and token of this user is revoked now."
            confirmLabel="Sign out everywhere"
            success="All sessions revoked"
            action={() => revokeUserSessions(realm, user.id)}
          />
        </div>
        <p className="flex gap-4 text-[13px]">
          <NavLink
            href={`${realmBase}/sessions?user=${encodeURIComponent(user.id)}`}
            className="text-accent hover:underline"
          >
            View sessions
          </NavLink>
          <NavLink
            href={`${realmBase}/audit?user=${encodeURIComponent(user.id)}`}
            className="text-accent hover:underline"
          >
            View audit trail
          </NavLink>
        </p>
      </section>

      <section className="rounded-lg border border-danger-soft p-4">
        <h3 className="text-[13px] font-semibold text-danger">Delete this user</h3>
        <p className="mt-1 mb-3 text-[12px] text-text-muted">
          The account is removed and signed out everywhere. Prefer &quot;Inactive&quot; to keep it for the records.
        </p>
        <ConfirmAction
          size="sm"
          disabled={locked}
          trigger={
            <>
              <Trash2 className="size-3.5" />
              Delete user
            </>
          }
          title={`Delete ${user.username}?`}
          description="This cannot be undone."
          confirmLabel="Delete user"
          success="User deleted"
          action={() => deleteUser(realm, user.id)}
          onDone={onDeleted}
        />
      </section>

      <Dialog open={resetOpen} onOpenChange={setResetOpen}>
        <DialogContent>
          <DialogTitle>Reset the MFA of {user.username}?</DialogTitle>
          <DialogDescription>
            Every factor and backup code is deleted and the user is signed out everywhere. They set up a new factor at
            the next sign-in. Check who asked first: this is a classic social-engineering target.
          </DialogDescription>
          <Field label="Reason (kept in the audit log)" htmlFor="mfa-reason" className="mt-4">
            <Textarea
              id="mfa-reason"
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Lost phone, identity checked by video call"
            />
          </Field>
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setResetOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              loading={pending}
              disabled={pending || reason.trim().length < 3}
              onClick={async () => {
                const r = await run(() => resetUserMfa(realm, user.id, reason.trim()), { success: "MFA reset" });
                if (r.ok) {
                  setResetOpen(false);
                  setReason("");
                }
              }}
            >
              Reset MFA
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
