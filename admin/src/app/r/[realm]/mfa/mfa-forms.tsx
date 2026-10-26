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
import { MFA_METHOD_LABELS } from "@/lib/labels";
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
  const [required, setRequired] = useState(policies.required_globally);
  const [maxAge, setMaxAge] = useState(String(policies.step_up_max_age_minutes));
  const { locked, banner } = useEditLock({ canWrite: writable });
  const { run, pending } = useAction();
  const dirty = required !== policies.required_globally || maxAge !== String(policies.step_up_max_age_minutes);
  return (
    <Card>
      <CardTitle>Realm policy</CardTitle>
      <CardDescription>Applies to every account; roles and clients can only make it stricter.</CardDescription>
      <div className="mt-4 space-y-4">
        {banner}
        <div className="flex items-center justify-between gap-4 rounded-lg border border-border px-4 py-3">
          <div>
            <p className="text-[14px] font-medium">Require a second factor for every account</p>
            {system && (
              <p className="text-[12px] text-text-muted">
                Always on in the master realm: its accounts administer the whole instance.
              </p>
            )}
          </div>
          <TogglePill
            checked={required}
            onCheckedChange={locked || system ? undefined : setRequired}
            onLabel="Required"
            offLabel="Optional"
            label="MFA required for every account"
          />
        </div>
        <Field
          label="Step-up window (minutes)"
          htmlFor="mfa-age"
          hint="How recent a second factor must be for sensitive actions (changing a password, every change in this console...). 1 to 1440."
        >
          <Input
            id="mfa-age"
            type="number"
            min={1}
            max={1440}
            value={maxAge}
            onChange={(e) => setMaxAge(e.target.value)}
            disabled={locked}
            className="w-32"
          />
        </Field>
        <Button
          loading={pending}
          disabled={locked || pending || !dirty}
          onClick={() =>
            run(
              () =>
                setRealmMfa(realm, {
                  required_globally: system ? undefined : required,
                  step_up_max_age_minutes: Number(maxAge),
                }),
              { success: "Realm MFA policy saved" },
            )
          }
        >
          Save
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
  const managed = policy.managed_by === "config";
  if (!writable || managed) return null;
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => stepUp.ensure(() => setOpen(true))}>
        Edit
      </Button>
      {policy.configured && (
        <ConfirmAction
          variant="secondary"
          trigger="Reset"
          title={`Back to the realm policy for ${policy.role.name}?`}
          description="This role's own MFA rules are removed: the realm policy applies."
          confirmLabel="Reset"
          confirmVariant="primary"
          success="Role policy removed"
          action={() => deleteRoleMfa(realm, policy.role.id)}
        />
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogTitle>MFA for the role {policy.role.name}</DialogTitle>
          <DialogDescription>Members of this role follow these rules on top of the realm policy.</DialogDescription>
          <div className="mt-5 space-y-4">
            <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
              <span className="text-[14px] font-medium">Second factor required</span>
              <TogglePill
                checked={required}
                onCheckedChange={setRequired}
                onLabel="Required"
                offLabel="Optional"
                label="Required"
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border border-border px-4 py-3">
              <span className="text-[14px] font-medium">Step-up for sensitive actions</span>
              <TogglePill
                checked={stepUpSensitive}
                onCheckedChange={setStepUpSensitive}
                label="Step-up for sensitive actions"
              />
            </div>
            <Field label="Accepted methods" hint="None selected: any method.">
              <ChipSelect
                label="Accepted methods"
                options={known.map((m) => ({ id: m, name: MFA_METHOD_LABELS[m] ?? m }))}
                value={methods}
                onChange={setMethods}
              />
            </Field>
            <Field
              label="Enrollment grace period (days)"
              htmlFor="r-grace"
              hint="Time new members get to set up a factor before it is enforced."
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
              Cancel
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
                  { quiet: true, success: "Role policy saved" },
                );
                if (r.ok) setOpen(false);
                else setError(r.message);
              }}
            >
              Save
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
