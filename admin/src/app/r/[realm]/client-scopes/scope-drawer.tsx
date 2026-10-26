"use client";

import { Plus, X } from "lucide-react";
import { useState } from "react";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { ChipSelect } from "@/components/ui/chip-select";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { TogglePill } from "@/components/ui/toggle-pill";
import { TOKEN_LOCATIONS } from "@/lib/labels";
import type { ClaimMapper, ClientScope } from "@/lib/types";
import { createScope, deleteScope, updateScope, type ScopeBody } from "./actions";

type Draft = {
  name: string;
  description: string;
  protocol: ClientScope["protocol"];
  isDefault: boolean;
  mappers: ClaimMapper[];
};

const empty: Draft = { name: "", description: "", protocol: "oidc", isDefault: false, mappers: [] };

function toDraft(s: ClientScope | null): Draft {
  if (!s) return empty;
  return {
    name: s.name,
    description: s.description,
    protocol: s.protocol,
    isDefault: s.is_default,
    mappers: s.claim_mappers.map((m) => ({ ...m, token_location: [...m.token_location] })),
  };
}

export function NewScopeButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      New client scope
    </Button>
  );
}

export function ScopeRowActions({ realm, scope, writable }: { realm: string; scope: ClientScope; writable: boolean }) {
  const { openEdit } = useDrawerUrl();
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(scope.id)}>
        {writable ? "Edit" : "View"}
      </Button>
      {writable && (
        <ConfirmAction
          trigger="Delete"
          title={`Delete the scope ${scope.name}?`}
          description={
            scope.clients > 0
              ? `${scope.clients} client(s) use it: remove it from them first.`
              : "Its claims will no longer be issued. This cannot be undone."
          }
          confirmLabel="Delete scope"
          success="Client scope deleted"
          action={() => deleteScope(realm, scope.id)}
        />
      )}
    </div>
  );
}

export function ScopeDrawer({
  realm,
  mode,
  scope,
  writable,
}: {
  realm: string;
  mode: "create" | "edit" | null;
  scope: ClientScope | null;
  writable: boolean;
}) {
  const { close } = useDrawerUrl();
  const { run, pending } = useAction();
  const [draft, setDraft] = useState<Draft>(() => toDraft(scope));
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const key = mode === "create" ? "new" : (scope?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(toDraft(scope));
    setError(null);
  }
  const { locked, banner } = useEditLock({
    canWrite: writable,
    intent: mode === "create" ? "new=1" : scope ? `edit=${scope.id}` : undefined,
  });
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const setMapper = (i: number, m: Partial<ClaimMapper>) =>
    set(
      "mappers",
      draft.mappers.map((x, j) => (j === i ? { ...x, ...m } : x)),
    );

  async function save() {
    setError(null);
    const body: ScopeBody = {
      name: draft.name.trim(),
      description: draft.description.trim(),
      protocol: draft.protocol,
      is_default: draft.isDefault,
      claim_mappers: draft.mappers.filter((m) => m.source_attribute.trim() || m.claim_name.trim()),
    };
    const r =
      mode === "create"
        ? await run(() => createScope(realm, body), { quiet: true, success: "Client scope created" })
        : await run(() => updateScope(realm, scope!.id, body), { quiet: true, success: "Client scope saved" });
    if (!r.ok) setError({ field: r.field, message: r.message });
    else if (mode === "create") close();
  }

  return (
    <Drawer
      open={mode !== null}
      onClose={close}
      title={mode === "create" ? "New client scope" : (scope?.name ?? "")}
      description="A named set of claims. Clients that receive it get these user attributes."
      footer={
        <>
          <Button onClick={save} loading={pending} disabled={locked || pending}>
            {pending ? "Saving…" : mode === "create" ? "Create scope" : "Save"}
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
        <Field
          label="Name"
          htmlFor="s-name"
          hint="The scope value clients ask for, e.g. payroll_profile."
          error={error?.field === "name" ? error.message : undefined}
        >
          <Input
            id="s-name"
            className="font-mono"
            value={draft.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="my_custom_scope"
          />
        </Field>
        <Field label="Description" htmlFor="s-desc" optional hint="Shown to users on the consent screen.">
          <Textarea
            id="s-desc"
            rows={2}
            value={draft.description}
            onChange={(e) => set("description", e.target.value)}
          />
        </Field>
        <Field label="Protocol">
          <Segmented
            label="Protocol"
            value={draft.protocol}
            onChange={(v) => set("protocol", v)}
            disabled={locked}
            options={[
              { value: "oidc", label: "OIDC" },
              { value: "saml2", label: "SAML 2.0" },
              { value: "both", label: "Both" },
            ]}
          />
        </Field>
        <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">Include by default on new clients</p>
            <p className="text-[12px] text-text-muted">Pre-selected as required when a client is created.</p>
          </div>
          <TogglePill
            checked={draft.isDefault}
            onCheckedChange={locked ? undefined : (v) => set("isDefault", v)}
            label="Default"
          />
        </div>
        <div>
          <div className="mb-2 flex items-center justify-between">
            <p className="text-[13px] font-semibold text-text-secondary">Claim mappers</p>
            {!locked && (
              <Button
                size="xs"
                variant="secondary"
                onClick={() =>
                  set("mappers", [
                    ...draft.mappers,
                    { source_attribute: "", claim_name: "", token_location: ["id_token", "userinfo"] },
                  ])
                }
              >
                <Plus className="size-3.5" />
                Add mapper
              </Button>
            )}
          </div>
          {error?.field === "claim_mappers" && <p className="mb-2 text-[12px] text-danger">{error.message}</p>}
          {draft.mappers.length === 0 && (
            <p className="text-[13px] text-text-muted">No claim yet: user attribute → claim name.</p>
          )}
          <div className="space-y-3">
            {draft.mappers.map((m, i) => (
              <div key={i} className="space-y-3 rounded-lg border border-border p-3">
                <div className="flex items-center gap-2">
                  <Input
                    aria-label="User attribute"
                    className="h-9 font-mono text-[13px]"
                    value={m.source_attribute}
                    onChange={(e) => setMapper(i, { source_attribute: e.target.value })}
                    placeholder="user attribute (department)"
                  />
                  <span className="text-text-muted">→</span>
                  <Input
                    aria-label="Claim name"
                    className="h-9 font-mono text-[13px]"
                    value={m.claim_name}
                    onChange={(e) => setMapper(i, { claim_name: e.target.value })}
                    placeholder="claim name"
                  />
                  {!locked && (
                    <button
                      type="button"
                      aria-label="Remove this mapper"
                      onClick={() =>
                        set(
                          "mappers",
                          draft.mappers.filter((_, j) => j !== i),
                        )
                      }
                      className="rounded-sm p-1 text-text-muted hover:bg-surface-alt hover:text-danger"
                    >
                      <X className="size-4" />
                    </button>
                  )}
                </div>
                <ChipSelect
                  label="Token locations"
                  options={TOKEN_LOCATIONS.map((l) => ({ id: l.value, name: l.label }))}
                  value={m.token_location}
                  onChange={(v) => setMapper(i, { token_location: v })}
                  disabled={locked}
                />
              </div>
            ))}
          </div>
        </div>
      </fieldset>
    </Drawer>
  );
}
