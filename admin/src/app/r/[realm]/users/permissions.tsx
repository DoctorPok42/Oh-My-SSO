"use client";

import { Plus } from "lucide-react";
import { useState } from "react";
import { ConfirmAction } from "@/components/console/confirm";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useT } from "@/i18n/client";
import type { Permission } from "@/lib/types";
import { createPermission, deletePermission } from "./actions";

// The realm's permission catalogue: "resource:action" pairs that roles and
// groups grant, and that applications check (RBAC).
export function NewPermissionButton({ realm }: { realm: string }) {
  const [open, setOpen] = useState(false);
  const [resource, setResource] = useState("");
  const [action, setAction] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const stepUp = useStepUp();
  const { run, pending } = useAction();
  const { t } = useT();
  return (
    <>
      <Button onClick={() => stepUp.ensure(() => setOpen(true))}>
        <Plus />
        {t("permissions.new", "New permission")}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogTitle>{t("permissions.new", "New permission")}</DialogTitle>
          <DialogDescription>
            {t("permissions.new_description", "Applications check it as resource:action, e.g. invoice:approve.")}
          </DialogDescription>
          <form
            className="mt-5 space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              setError(null);
              const r = await run(
                () =>
                  createPermission(realm, {
                    resource: resource.trim(),
                    action: action.trim(),
                    description: description.trim(),
                  }),
                {
                  quiet: true,
                  success: t("permissions.created", "Permission created"),
                },
              );
              if (!r.ok) return setError({ field: r.field, message: r.message });
              setOpen(false);
              setResource("");
              setAction("");
              setDescription("");
            }}
          >
            <div className="grid grid-cols-2 gap-3">
              <Field
                label={t("permissions.resource", "Resource")}
                htmlFor="p-res"
                error={error?.field === "resource" ? error.message : undefined}
              >
                <Input
                  id="p-res"
                  className="font-mono"
                  value={resource}
                  onChange={(e) => setResource(e.target.value)}
                  placeholder="invoice"
                />
              </Field>
              <Field
                label={t("permissions.action", "Action")}
                htmlFor="p-act"
                error={error?.field === "action" ? error.message : undefined}
              >
                <Input
                  id="p-act"
                  className="font-mono"
                  value={action}
                  onChange={(e) => setAction(e.target.value)}
                  placeholder="approve"
                />
              </Field>
            </div>
            <Field label={t("scopes.field.description", "Description")} htmlFor="p-desc" optional>
              <Input id="p-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
            </Field>
            {error && !error.field && <p className="text-[12px] text-danger">{error.message}</p>}
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setOpen(false)}>
                {t("common.cancel", "Cancel")}
              </Button>
              <Button type="submit" loading={pending} disabled={pending || !resource.trim() || !action.trim()}>
                {t("common.create", "Create")}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

export function PermissionDelete({ realm, permission }: { realm: string; permission: Permission }) {
  const { t } = useT();
  return (
    <ConfirmAction
      trigger={t("common.delete", "Delete")}
      title={t("clients.delete.title", "Delete {name}?", { name: permission.name })}
      description={t(
        "permissions.delete_text",
        "Roles and groups that grant it lose it. Applications that check it will deny access.",
      )}
      confirmLabel={t("permissions.delete_confirm", "Delete permission")}
      success={t("permissions.deleted", "Permission deleted")}
      action={() => deletePermission(realm, permission.id)}
    />
  );
}
