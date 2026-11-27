"use client";

import { Plus } from "lucide-react";
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
import { useT } from "@/i18n/client";
import type { ApiResource, ClientScope } from "@/lib/types";
import { createApiResource, deleteApiResource, updateApiResource, type ApiResourceBody } from "./actions";

type Draft = { identifier: string; name: string; description: string; scopeIds: string[] };

function toDraft(r: ApiResource | null): Draft {
  if (!r) return { identifier: "", name: "", description: "", scopeIds: [] };
  return { identifier: r.identifier, name: r.name, description: r.description, scopeIds: r.scopes.map((s) => s.id) };
}

export function NewApiResourceButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  const { t } = useT();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      {t("api_resources.new", "New API resource")}
    </Button>
  );
}

export function ApiResourceRowActions({
  realm,
  resource,
  writable,
}: {
  realm: string;
  resource: ApiResource;
  writable: boolean;
}) {
  const { openEdit } = useDrawerUrl();
  const { t } = useT();
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(resource.id)}>
        {writable ? t("common.edit", "Edit") : t("common.view", "View")}
      </Button>
      {writable && (
        <ConfirmAction
          trigger={t("common.delete", "Delete")}
          title={t("api_resources.delete.title", "Delete the API resource {name}?", { name: resource.name })}
          description={t(
            "api_resources.delete.text",
            "Clients can no longer ask for tokens meant for it. Tokens already issued stay valid until they expire, but the users of applications that asked for it must sign in again.",
          )}
          confirmLabel={t("api_resources.delete.confirm", "Delete API resource")}
          success={t("api_resources.delete.done", "API resource deleted")}
          action={() => deleteApiResource(realm, resource.id)}
        />
      )}
    </div>
  );
}

export function ApiResourceDrawer({
  realm,
  mode,
  resource,
  scopes,
  writable,
}: {
  realm: string;
  mode: "create" | "edit" | null;
  resource: ApiResource | null;
  /** The OIDC client scopes of the realm. */
  scopes: ClientScope[];
  writable: boolean;
}) {
  const { close } = useDrawerUrl();
  const { run, pending } = useAction();
  const { t } = useT();
  const [draft, setDraft] = useState<Draft>(() => toDraft(resource));
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const key = mode === "create" ? "new" : (resource?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(toDraft(resource));
    setError(null);
  }
  const { locked, banner } = useEditLock({
    canWrite: writable,
    intent: mode === "create" ? "new=1" : resource ? `edit=${resource.id}` : undefined,
  });
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const err = (field: string) => (error?.field === field ? error.message : undefined);

  async function save() {
    setError(null);
    const body: ApiResourceBody = {
      name: draft.name.trim(),
      description: draft.description.trim(),
      scope_ids: draft.scopeIds,
    };
    if (mode === "create") body.identifier = draft.identifier.trim();
    const r =
      mode === "create"
        ? await run(() => createApiResource(realm, body), {
            quiet: true,
            success: t("api_resources.created", "API resource created"),
          })
        : await run(() => updateApiResource(realm, resource!.id, body), {
            quiet: true,
            success: t("api_resources.saved", "API resource saved"),
          });
    if (!r.ok) setError({ field: r.field, message: r.message });
    else if (mode === "create") close();
  }

  return (
    <Drawer
      open={mode !== null}
      onClose={close}
      title={mode === "create" ? t("api_resources.new", "New API resource") : (resource?.name ?? "")}
      description={t(
        "api_resources.description",
        'A client names this API in the "resource" parameter (RFC 8707): its access token then carries the identifier in "aud" and only the API\'s scopes.',
      )}
      footer={
        <>
          <Button onClick={save} loading={pending} disabled={locked || pending}>
            {pending
              ? t("common.saving", "Saving…")
              : mode === "create"
                ? t("api_resources.create", "Create API resource")
                : t("common.save", "Save")}
          </Button>
          <Button variant="secondary" onClick={close}>
            {t("common.cancel", "Cancel")}
          </Button>
        </>
      }
    >
      {banner}
      {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
      <fieldset disabled={locked} className="space-y-5">
        <Field
          label={t("api_resources.field.identifier", "Identifier")}
          htmlFor="r-identifier"
          hint={
            mode === "create"
              ? t(
                  "api_resources.field.identifier_hint",
                  'The value the API checks in "aud", usually its base URL. It cannot change later.',
                )
              : t("api_resources.field.identifier_fixed", "It cannot change: the API checks it in its tokens.")
          }
          error={err("identifier")}
        >
          <Input
            id="r-identifier"
            autoFocus={mode === "create"}
            className="font-mono"
            value={draft.identifier}
            readOnly={mode !== "create"}
            onChange={(e) => set("identifier", e.target.value)}
            placeholder="https://api.example.com"
          />
        </Field>
        <Field
          label={t("clients.field.name", "Name")}
          htmlFor="r-name"
          optional={mode === "create"}
          hint={mode === "create" ? t("api_resources.field.name_hint", "Empty: the identifier.") : undefined}
          error={err("name")}
        >
          <Input id="r-name" value={draft.name} onChange={(e) => set("name", e.target.value)} />
        </Field>
        <Field label={t("scopes.field.description", "Description")} htmlFor="r-desc" optional>
          <Textarea
            id="r-desc"
            rows={2}
            value={draft.description}
            onChange={(e) => set("description", e.target.value)}
          />
        </Field>
        <Field
          label={t("api_resources.field.scopes", "Scopes of this API")}
          hint={t(
            "api_resources.field.scopes_hint",
            "A client may ask for this API only if it may have one of these scopes; its tokens for the API keep only them (and openid, profile, email).",
          )}
          error={err("scope_ids")}
        >
          <ChipSelect
            label={t("api_resources.field.scopes", "Scopes of this API")}
            options={scopes.map((s) => ({ id: s.id, name: s.name }))}
            value={draft.scopeIds}
            onChange={(v) => set("scopeIds", v)}
            disabled={locked}
          />
        </Field>
      </fieldset>
    </Drawer>
  );
}
