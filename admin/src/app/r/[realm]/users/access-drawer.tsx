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
import type { Access, ClientScope, Permission, UserSummary } from "@/lib/types";
import { deleteAccess, saveAccess } from "./actions";

// Roles and groups have the same shape (name, permissions, granted client
// scopes); the drawer serves both. Groups are the recommended way: they
// gather people, so "who can do what" stays readable.

type Kind = "roles" | "groups";

export function NewAccessButton({ kind }: { kind: Kind }) {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      {kind === "roles" ? "New role" : "New group"}
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
  const editable = writable && item.managed_by !== "config";
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(item.id)}>
        {editable ? "Edit" : "View"}
      </Button>
      {editable && (
        <ConfirmAction
          trigger="Delete"
          title={`Delete the ${kind === "roles" ? "role" : "group"} ${item.name}?`}
          description={
            item.members > 0
              ? `${item.members} user(s) lose the access it gives, at once.`
              : "Nobody has it. This cannot be undone."
          }
          confirmLabel="Delete"
          success={kind === "roles" ? "Role deleted" : "Group deleted"}
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
  /** timeout:write: a group's footer offers "Suspend…" (Timeouts page). */
  canSuspend?: boolean;
}) {
  const { close } = useDrawerUrl();
  const { run, pending } = useAction();
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
  const noun = kind === "roles" ? "role" : "group";

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
      { quiet: true, success: mode === "create" ? `The ${noun} was created` : "Saved" },
    );
    if (!r.ok) return setError({ field: r.field, message: r.message });
    if (mode === "create") close();
  }

  return (
    <Drawer
      open={mode !== null}
      onClose={close}
      title={mode === "create" ? `New ${noun}` : (item?.name ?? "")}
      description={
        kind === "groups" ? "People who share the same access." : "A set of permissions given to users one by one."
      }
      footer={
        <>
          <Button onClick={save} loading={pending} disabled={locked || pending}>
            {pending ? "Saving…" : mode === "create" ? `Create ${noun}` : "Save"}
          </Button>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          {kind === "groups" && mode === "edit" && item && canSuspend && (
            <SuspendLink className="ml-auto" realm={realm} type="group" id={item.id} name={item.name} />
          )}
        </>
      }
    >
      {banner}
      {kind === "roles" && (
        // The API's own wording (domain.RoleSecurityNotice) when it sent one.
        <Banner tone="warning">
          {item?.notice || "Less auditable than a group at scale. Prefer giving access through groups when possible."}
        </Banner>
      )}
      {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
      <fieldset disabled={locked} className="space-y-5">
        <Field label="Name" htmlFor="a-name" error={error?.field === "name" ? error.message : undefined}>
          <Input
            id="a-name"
            value={draft.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder={kind === "roles" ? "payroll-manager" : "finance"}
          />
        </Field>
        <Field label="Description" htmlFor="a-desc" optional>
          <Textarea
            id="a-desc"
            rows={2}
            value={draft.description}
            onChange={(e) => set("description", e.target.value)}
          />
        </Field>
        <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">Active</p>
            <p className="text-[12px] text-text-muted">An inactive {noun} gives nothing, but keeps its members.</p>
          </div>
          <TogglePill
            checked={draft.active}
            onCheckedChange={locked ? undefined : (v) => set("active", v)}
            label="Active"
          />
        </div>
        <Field label="Permissions" hint="What members may do in the applications that check them (RBAC).">
          <ChipSelect
            label="Permissions"
            options={permissions.map((p) => ({ id: p.id, name: p.name, hint: p.description }))}
            value={draft.permissionIds}
            onChange={(v) => set("permissionIds", v)}
            disabled={locked}
            empty="No permission in this realm yet (Permissions tab)."
          />
        </Field>
        <Field label="Granted client scopes" hint="Claim sets members receive in their tokens.">
          <ChipSelect
            label="Granted client scopes"
            options={scopes.map((s) => ({ id: s.id, name: s.name, hint: s.description }))}
            value={draft.scopeIds}
            onChange={(v) => set("scopeIds", v)}
            disabled={locked}
            empty="No client scope in this realm."
          />
        </Field>
      </fieldset>
      {kind === "groups" && mode === "edit" && members && (
        <section className="border-t border-border pt-5">
          <h3 className="mb-2 text-[13px] font-semibold text-text-secondary">
            Members <span className="font-normal text-text-muted">({item?.members ?? members.length})</span>
          </h3>
          {members.length === 0 ? (
            <p className="text-[13px] text-text-muted">Nobody yet. Add users to this group from their page.</p>
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
        </section>
      )}
    </Drawer>
  );
}
