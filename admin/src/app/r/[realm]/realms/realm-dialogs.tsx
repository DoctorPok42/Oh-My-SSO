"use client";

import { Plus } from "lucide-react";
import { useNavigate } from "@/components/console/navigation-progress";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmAction } from "@/components/console/confirm";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useT } from "@/i18n/client";
import type { Realm } from "@/lib/types";
import { createRealm, updateRealm } from "./actions";

/** "Nova Industries" -> "nova-industries" (the realm's name in URLs). */
export function slugify(v: string): string {
  return v
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

export function NewRealmButton() {
  const [open, setOpen] = useState(false);
  const [display, setDisplay] = useState("");
  const [name, setName] = useState("");
  const [touched, setTouched] = useState(false);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const stepUp = useStepUp();
  const router = useNavigate();
  const { run, pending } = useAction();
  const { t } = useT();
  const slug = touched ? name : slugify(display);
  return (
    <>
      <Button onClick={() => stepUp.ensure(() => setOpen(true))}>
        <Plus />
        {t("realms.new", "New realm")}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogTitle>{t("realms.new", "New realm")}</DialogTitle>
          <DialogDescription>
            {t(
              "realms.new_description",
              "A separate space with its own users, applications, keys and policies (one per organization or environment).",
            )}
          </DialogDescription>
          <form
            className="mt-5 space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              setError(null);
              const r = await run(() => createRealm({ name: slug, display_name: display.trim() }), { quiet: true });
              if (!r.ok) return setError({ field: r.field, message: r.message });
              setOpen(false);
              toast.success(t("realms.created", "Realm {name} created", { name: r.data.realm.display_name }));
              if (r.data.warning) toast.warning(r.data.warning, { duration: 12_000 });
              router.push(`/r/${encodeURIComponent(r.data.realm.name)}/dashboard`);
            }}
          >
            <Field
              label={t("columns.display_name", "Display name")}
              htmlFor="r-display"
              error={error?.field === "display_name" ? error.message : undefined}
            >
              <Input
                id="r-display"
                value={display}
                onChange={(e) => setDisplay(e.target.value)}
                placeholder="Nova Industries"
              />
            </Field>
            <Field
              label={t("clients.field.name", "Name")}
              htmlFor="r-name"
              hint={t(
                "realms.name_hint",
                "Lowercase letters, digits and dashes. In every URL: /r/{slug}/… It cannot change later.",
                { slug: slug || "<name>" },
              )}
              error={error?.field === "name" ? error.message : undefined}
            >
              <Input
                id="r-name"
                className="font-mono"
                value={slug}
                onChange={(e) => {
                  setTouched(true);
                  setName(e.target.value.toLowerCase());
                }}
                placeholder="nova"
              />
            </Field>
            {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setOpen(false)}>
                {t("common.cancel", "Cancel")}
              </Button>
              <Button type="submit" loading={pending} disabled={pending || !slug || !display.trim()}>
                {pending ? t("realms.creating", "Creating…") : t("realms.create", "Create realm")}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

export function RealmRowActions({ realm, writable }: { realm: Realm; writable: boolean }) {
  const [open, setOpen] = useState(false);
  const [display, setDisplay] = useState(realm.display_name);
  const [error, setError] = useState<string | null>(null);
  const stepUp = useStepUp();
  const { run, pending } = useAction();
  const { t } = useT();
  if (!writable) return null;
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => stepUp.ensure(() => setOpen(true))}>
        {t("realms.rename", "Rename")}
      </Button>
      {!realm.system &&
        (realm.status === "active" ? (
          <ConfirmAction
            trigger={t("realms.disable", "Disable")}
            title={t("realms.disable_title", "Disable {name}?", { name: realm.display_name })}
            description={t(
              "realms.disable_text",
              "Nobody can sign in to this realm's applications any more, and its sessions end. Everything is kept: enable it again at any time.",
            )}
            confirmLabel={t("realms.disable_confirm", "Disable realm")}
            success={t("realms.disabled", "Realm disabled")}
            action={() => updateRealm(realm.name, { status: "inactive" })}
          />
        ) : (
          <ConfirmAction
            variant="secondary"
            trigger={t("realms.enable", "Enable")}
            title={t("realms.enable_title", "Enable {name}?", { name: realm.display_name })}
            description={t("realms.enable_text", "Users can sign in again.")}
            confirmLabel={t("realms.enable_confirm", "Enable realm")}
            confirmVariant="primary"
            success={t("realms.enabled", "Realm enabled")}
            action={() => updateRealm(realm.name, { status: "active" })}
          />
        ))}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogTitle>{t("realms.rename_title", "Rename {name}", { name: realm.name })}</DialogTitle>
          <DialogDescription>
            {t("realms.rename_text", "Only the display name changes; the name in URLs stays {name}.", {
              name: realm.name,
            })}
          </DialogDescription>
          <form
            className="mt-5 space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              setError(null);
              const r = await run(() => updateRealm(realm.name, { display_name: display.trim() }), {
                quiet: true,
                success: t("realms.renamed", "Realm renamed"),
              });
              if (r.ok) setOpen(false);
              else setError(r.message);
            }}
          >
            <Field
              label={t("columns.display_name", "Display name")}
              htmlFor={`rn-${realm.id}`}
              error={error ?? undefined}
            >
              <Input id={`rn-${realm.id}`} value={display} onChange={(e) => setDisplay(e.target.value)} />
            </Field>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setOpen(false)}>
                {t("common.cancel", "Cancel")}
              </Button>
              <Button type="submit" loading={pending} disabled={pending || !display.trim()}>
                {t("common.save", "Save")}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
