"use client";

import { Plus } from "lucide-react";
import { useState } from "react";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { SuspendLink } from "@/components/console/suspend-link";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { ChipSelect } from "@/components/ui/chip-select";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { TogglePill } from "@/components/ui/toggle-pill";
import { useT } from "@/i18n/client";
import type { Access, ClientScope, Permission, UserSummary } from "@/lib/types";
import { deleteAccess, saveAccess } from "./actions";
import { AddGroupMembers, GroupMembers } from "./group-members";

// Roles and groups have the same shape (name, permissions, granted client
// scopes); the drawer serves both. Groups are the recommended way: they
// gather people, so "who can do what" stays readable. Their texts have one
// key each (a role, a group): languages do not word them alike.

type Kind = "roles" | "groups";

export function NewAccessButton({ kind }: { kind: Kind }) {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  const { t } = useT();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      {kind === "roles" ? t("access.role.new", "New role") : t("access.group.new", "New group")}
    </Button>
  );
}

export function AccessRowActions({
  realm,
  kind,
  item,
  writable,
}: {
  realm: string;
  kind: Kind;
  item: Access;
  writable: boolean;
}) {
  const { openEdit } = useDrawerUrl();
  const { t, tn } = useT();
  const editable = writable && item.managed_by !== "config";
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(item.id)}>
        {editable ? t("common.edit", "Edit") : t("common.view", "View")}
      </Button>
      {editable && (
        <ConfirmAction
          trigger={t("common.delete", "Delete")}
          title={
            kind === "roles"
              ? t("access.role.delete_title", "Delete the role {name}?", { name: item.name })
              : t("access.group.delete_title", "Delete the group {name}?", { name: item.name })
          }
          description={
            item.members > 0
              ? tn(
                  "access.delete_members",
                  item.members,
                  "{count} user loses the access it gives, at once.",
                  "{count} users lose the access it gives, at once.",
                )
              : t("access.delete_nobody", "Nobody has it. This cannot be undone.")
          }
          confirmLabel={t("common.delete", "Delete")}
          success={
            kind === "roles" ? t("access.role.deleted", "Role deleted") : t("access.group.deleted", "Group deleted")
          }
          action={() => deleteAccess(realm, kind, item.id)}
        />
      )}
    </div>
  );
}

type Draft = { name: string; description: string; active: boolean; permissionIds: string[]; scopeIds: string[] };

const toDraft = (a: Access | null): Draft =>
  a
    ? {
        name: a.name,
        description: a.description,
        active: a.status === "active",
        permissionIds: a.permission_ids,
        scopeIds: a.client_scope_ids,
      }
    : { name: "", description: "", active: true, permissionIds: [], scopeIds: [] };

export function AccessDrawer({
  realm,
  kind,
  mode,
  item,
  permissions,
  scopes,
  members,
  writable,
  canAddMembers = false,
  canSuspend = false,
}: {
  realm: string;
  kind: Kind;
  mode: "create" | "edit" | null;
  item: Access | null;
  permissions: Permission[];
  scopes: ClientScope[];
  members: UserSummary[] | null;
  writable: boolean;
  /** user:write: the members of a group can be added from a pasted list, and removed on a selection. */
  canAddMembers?: boolean;
  /** timeout:write: a group's footer offers "Suspend…" (Timeouts page). */
  canSuspend?: boolean;
}) {
  const { close } = useDrawerUrl();
  const { run, pending } = useAction();
  const { t } = useT();
  const [draft, setDraft] = useState<Draft>(() => toDraft(item));
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const key = mode === "create" ? "new" : (item?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(toDraft(item));
    setError(null);
  }
  const { locked, banner } = useEditLock({
    canWrite: writable,
    managedByConfig: item?.managed_by === "config",
    intent: mode === "create" ? "new=1" : item ? `edit=${item.id}` : undefined,
  });
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const roles = kind === "roles";

  async function save() {
    setError(null);
    const r = await run(
      () =>
        saveAccess(realm, kind, mode === "edit" && item ? item.id : null, {
          name: draft.name.trim(),
          description: draft.description.trim(),
          active: draft.active,
          permission_ids: draft.permissionIds,
          client_scope_ids: draft.scopeIds,
        }),
      {
        quiet: true,
        success:
          mode === "create"
            ? roles
              ? t("access.role.created", "The role was created")
              : t("access.group.created", "The group was created")
            : t("access.saved", "Saved"),
      },
    );
    if (!r.ok) return setError({ field: r.field, message: r.message });
    if (mode === "create") close();
  }

  return (
    <Drawer
      open={mode !== null}
      onClose={close}
      title={
        mode === "create"
          ? roles
            ? t("access.role.new", "New role")
            : t("access.group.new", "New group")
          : (item?.name ?? "")
      }
      description={
        roles
          ? t("access.role.description", "A set of permissions given to users one by one.")
          : t("access.group.description", "People who share the same access.")
      }
      footer={
        <>
          <Button onClick={save} loading={pending} disabled={locked || pending}>
            {pending
              ? t("common.saving", "Saving…")
              : mode === "create"
                ? roles
                  ? t("access.role.create", "Create role")
                  : t("access.group.create", "Create group")
                : t("common.save", "Save")}
          </Button>
          <Button variant="secondary" onClick={close}>
            {t("common.cancel", "Cancel")}
          </Button>
          {kind === "groups" && mode === "edit" && item && canSuspend && (
            <SuspendLink className="ml-auto" realm={realm} type="group" id={item.id} name={item.name} />
          )}
        </>
      }
    >
      {banner}
      {roles && (
        // The API's own wording (domain.RoleSecurityNotice) when it sent one.
        <Banner tone="warning">
          {item?.notice ||
            t(
              "access.role.notice",
              "Less auditable than a group at scale. Prefer giving access through groups when possible.",
            )}
        </Banner>
      )}
      {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
      <fieldset disabled={locked} className="space-y-5">
        <Field
          label={t("clients.field.name", "Name")}
          htmlFor="a-name"
          error={error?.field === "name" ? error.message : undefined}
        >
          <Input
            id="a-name"
            value={draft.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder={roles ? "payroll-manager" : "finance"}
          />
        </Field>
        <Field label={t("scopes.field.description", "Description")} htmlFor="a-desc" optional>
          <Textarea
            id="a-desc"
            rows={2}
            value={draft.description}
            onChange={(e) => set("description", e.target.value)}
          />
        </Field>
        <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">{t("status.active", "Active")}</p>
            <p className="text-[12px] text-text-muted">
              {roles
                ? t("access.role.inactive_hint", "An inactive role gives nothing, but keeps its members.")
                : t("access.group.inactive_hint", "An inactive group gives nothing, but keeps its members.")}
            </p>
          </div>
          <TogglePill
            checked={draft.active}
            onCheckedChange={locked ? undefined : (v) => set("active", v)}
            label={t("status.active", "Active")}
          />
        </div>
        <Field
          label={t("columns.permissions", "Permissions")}
          hint={t("access.permissions_hint", "What members may do in the applications that check them (RBAC).")}
        >
          <ChipSelect
            label={t("columns.permissions", "Permissions")}
            options={permissions.map((p) => ({ id: p.id, name: p.name, hint: p.description }))}
            value={draft.permissionIds}
            onChange={(v) => set("permissionIds", v)}
            disabled={locked}
            empty={t("access.no_permission", "No permission in this realm yet (Permissions tab).")}
          />
        </Field>
        <Field
          label={t("access.granted_scopes", "Granted client scopes")}
          hint={t("access.granted_scopes_hint", "Claim sets members receive in their tokens.")}
        >
          <ChipSelect
            label={t("access.granted_scopes", "Granted client scopes")}
            options={scopes.map((s) => ({ id: s.id, name: s.name, hint: s.description }))}
            value={draft.scopeIds}
            onChange={(v) => set("scopeIds", v)}
            disabled={locked}
            empty={t("access.no_scope", "No client scope in this realm.")}
          />
        </Field>
      </fieldset>
      {kind === "groups" && mode === "edit" && members && (
        <section className="border-t border-border pt-5">
          <h3 className="mb-2 text-[13px] font-semibold text-text-secondary">
            {t("columns.members", "Members")}{" "}
            <span className="font-normal text-text-muted">({item?.members ?? members.length})</span>
          </h3>
          {members.length === 0 ? (
            <p className="text-[13px] text-text-muted">
              {t("access.no_member", "Nobody yet. Add users to this group from their page.")}
            </p>
          ) : canAddMembers && item ? (
            <GroupMembers realm={realm} groupId={item.id} members={members} />
          ) : (
            <ul className="divide-y divide-border rounded-lg border border-border">
              {members.map((m) => (
                <li key={m.id} className="flex items-center justify-between px-3 py-2 text-[13px]">
                  <span className="font-medium">{m.name || m.username}</span>
                  <span className="text-text-muted">{m.email}</span>
                </li>
              ))}
            </ul>
          )}
          {canAddMembers && item && <AddGroupMembers realm={realm} groupId={item.id} />}
        </section>
      )}
    </Drawer>
  );
}
