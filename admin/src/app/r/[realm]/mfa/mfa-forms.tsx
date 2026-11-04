"use client";

import { useState } from "react";
import { ConfirmAction } from "@/components/console/confirm";
import { useEditLock } from "@/components/console/drawer";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { ChipSelect } from "@/components/ui/chip-select";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { TogglePill } from "@/components/ui/toggle-pill";
import { useT } from "@/i18n/client";
import { MFA_METHOD_LABELS } from "@/lib/labels";
import { realmMfaDraft, realmMfaPatch, TRUSTED_DEVICE_DAYS } from "@/lib/mfa-form";
import type { MfaPolicies, RolePolicy } from "@/lib/types";
import { deleteRoleMfa, setRealmMfa, setRoleMfa } from "./actions";

export function RealmMfaCard({
  realm,
  policies,
  writable,
  system,
}: {
  realm: string;
  policies: MfaPolicies;
  writable: boolean;
  system: boolean;
}) {
  const [draft, setDraft] = useState(() => realmMfaDraft(policies));
  const { required, maxAge, trusted, trustedDays } = draft;
  const set = <K extends keyof typeof draft>(k: K, v: (typeof draft)[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const setRequired = (v: boolean) => set("required", v);
  const { locked, banner } = useEditLock({ canWrite: writable });
  const { run, pending } = useAction();
  const { t } = useT();
  const patch = realmMfaPatch(policies, draft, system);
  const dirty = Object.keys(patch).length > 0;
  return (
    <Card>
      <CardTitle>{t("mfa.realm.title", "Realm policy")}</CardTitle>
      <CardDescription>
        {t("mfa.realm.description", "Applies to every account; roles and clients can only make it stricter.")}
      </CardDescription>
      <div className="mt-4 space-y-4">
        {banner}
        <div className="flex items-center justify-between gap-4 rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">
              {t("mfa.realm.required", "Require a second factor for every account")}
            </p>
            {system && (
              <p className="text-[12px] text-text-muted">
                {t("mfa.realm.master_on", "Always on in the master realm: its accounts administer the whole instance.")}
              </p>
            )}
          </div>
          <TogglePill
            checked={required}
            onCheckedChange={locked || system ? undefined : setRequired}
            onLabel={t("clients.scope.required", "Required")}
            offLabel={t("clients.scope.optional", "Optional")}
            label={t("mfa.realm.required_label", "MFA required for every account")}
          />
        </div>
        <Field
          label={t("mfa.realm.step_up", "Step-up window (minutes)")}
          htmlFor="mfa-age"
          hint={t(
            "mfa.realm.step_up_hint",
            "How recent a second factor must be for sensitive actions (changing a password, every change in this console...). 1 to 1440, and at most the session idle timeout (Settings): an idle session ends first.",
          )}
        >
          <Input
            id="mfa-age"
            type="number"
            min={1}
            max={1440}
            value={maxAge}
            onChange={(e) => set("maxAge", e.target.value)}
            disabled={locked}
            className="w-32"
          />
        </Field>
        <div className="flex items-center justify-between gap-4 rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">{t("mfa.realm.trusted", '"Don\'t ask again on this device"')}</p>
            <p className="text-[12px] text-text-muted">
              {system
                ? t(
                    "mfa.realm.trusted_master",
                    "Always off in the master realm: its accounts always give a second factor.",
                  )
                : t(
                    "mfa.realm.trusted_hint",
                    "After a second factor, users may skip it on that device. Applications and roles that require MFA still ask, and so does a sign-in that looks suspicious.",
                  )}
            </p>
          </div>
          <TogglePill
            checked={trusted}
            onCheckedChange={locked || system ? undefined : (v) => set("trusted", v)}
            onLabel={t("mfa.realm.offered", "Offered")}
            offLabel={t("mfa.realm.off", "Off")}
            label={t("mfa.realm.trusted_label", "Offer Don't ask again on this device")}
          />
        </div>
        {trusted && !system && (
          <Field
            label={t("mfa.realm.trusted_days", "Trusted for (days)")}
            htmlFor="mfa-trusted-days"
            hint={t(
              "mfa.realm.trusted_days_hint",
              "A fixed period from the moment the box is ticked. {min} to {max}.",
              {
                min: TRUSTED_DEVICE_DAYS.min,
                max: TRUSTED_DEVICE_DAYS.max,
              },
            )}
          >
            <Input
              id="mfa-trusted-days"
              type="number"
              min={TRUSTED_DEVICE_DAYS.min}
              max={TRUSTED_DEVICE_DAYS.max}
              value={trustedDays}
              onChange={(e) => set("trustedDays", e.target.value)}
              disabled={locked}
              className="w-32"
            />
          </Field>
        )}
        <Button
          loading={pending}
          disabled={locked || pending || !dirty}
          onClick={() =>
            run(() => setRealmMfa(realm, patch), { success: t("mfa.realm.saved", "Realm MFA policy saved") })
          }
        >
          {t("common.save", "Save")}
        </Button>
      </div>
    </Card>
  );
}

export function RolePolicyActions({
  realm,
  policy,
  known,
  writable,
}: {
  realm: string;
  policy: RolePolicy;
  known: string[];
  writable: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [required, setRequired] = useState(policy.required);
  const [methods, setMethods] = useState(policy.allowed_methods);
  const [grace, setGrace] = useState(String(policy.enrollment_grace_days));
  const [stepUpSensitive, setStepUpSensitive] = useState(policy.step_up_for_sensitive_actions);
  const [error, setError] = useState<string | null>(null);
  const stepUp = useStepUp();
  const { run, pending } = useAction();
  const { t, tm } = useT();
  const managed = policy.managed_by === "config";
  if (!writable || managed) return null;
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => stepUp.ensure(() => setOpen(true))}>
        {t("common.edit", "Edit")}
      </Button>
      {policy.configured && (
        <ConfirmAction
          variant="secondary"
          trigger={t("common.reset", "Reset")}
          title={t("mfa.role.reset_title", "Back to the realm policy for {role}?", { role: policy.role.name })}
          description={t("mfa.role.reset_text", "This role's own MFA rules are removed: the realm policy applies.")}
          confirmLabel={t("common.reset", "Reset")}
          confirmVariant="primary"
          success={t("mfa.role.removed", "Role policy removed")}
          action={() => deleteRoleMfa(realm, policy.role.id)}
        />
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogTitle>{t("mfa.role.title", "MFA for the role {role}", { role: policy.role.name })}</DialogTitle>
          <DialogDescription>
            {t("mfa.role.description", "Members of this role follow these rules on top of the realm policy.")}
          </DialogDescription>
          <div className="mt-5 space-y-4">
            <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
              <span className="text-[14px] font-medium">{t("mfa.role.required", "Second factor required")}</span>
              <TogglePill
                checked={required}
                onCheckedChange={setRequired}
                onLabel={t("clients.scope.required", "Required")}
                offLabel={t("clients.scope.optional", "Optional")}
                label={t("clients.scope.required", "Required")}
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
              <span className="text-[14px] font-medium">{t("columns.step_up", "Step-up for sensitive actions")}</span>
              <TogglePill
                checked={stepUpSensitive}
                onCheckedChange={setStepUpSensitive}
                label={t("columns.step_up", "Step-up for sensitive actions")}
              />
            </div>
            <Field
              label={t("clients.mfa.methods", "Accepted methods")}
              hint={t("mfa.role.methods_hint", "None selected: any method.")}
            >
              <ChipSelect
                label={t("clients.mfa.methods", "Accepted methods")}
                options={known.map((id) => {
                  const label = MFA_METHOD_LABELS[id];
                  return { id, name: label ? tm(label) : id };
                })}
                value={methods}
                onChange={setMethods}
              />
            </Field>
            <Field
              label={t("mfa.role.grace", "Enrollment grace period (days)")}
              htmlFor="r-grace"
              hint={t("mfa.role.grace_hint", "Time new members get to set up a factor before it is enforced.")}
            >
              <Input
                id="r-grace"
                type="number"
                min={0}
                value={grace}
                onChange={(e) => setGrace(e.target.value)}
                className="w-32"
              />
            </Field>
            {error && <Banner tone="danger">{error}</Banner>}
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)}>
              {t("common.cancel", "Cancel")}
            </Button>
            <Button
              loading={pending}
              disabled={pending}
              onClick={async () => {
                setError(null);
                const r = await run(
                  () =>
                    setRoleMfa(realm, policy.role.id, {
                      required,
                      allowed_methods: methods,
                      enrollment_grace_days: Number(grace) || 0,
                      step_up_for_sensitive_actions: stepUpSensitive,
                    }),
                  { quiet: true, success: t("mfa.role.saved", "Role policy saved") },
                );
                if (r.ok) setOpen(false);
                else setError(r.message);
              }}
            >
              {t("common.save", "Save")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
