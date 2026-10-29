import type { MfaPolicies } from "@/lib/types";

// The realm MFA form's helper (pure, unit-tested in tests/forms.test.ts).

export type RealmMfaDraft = { required: boolean; maxAge: string; trusted: boolean; trustedDays: string };

export type RealmMfaBody = {
  required_globally?: boolean;
  step_up_max_age_minutes?: number;
  trusted_devices_enabled?: boolean;
  trusted_device_days?: number;
};

export const TRUSTED_DEVICE_DAYS = { min: 1, max: 90 };

export function realmMfaDraft(p: MfaPolicies): RealmMfaDraft {
  return {
    required: p.required_globally,
    maxAge: String(p.step_up_max_age_minutes),
    trusted: p.trusted_devices_enabled,
    trustedDays: String(p.trusted_device_days),
  };
}

/** Only what changed is sent. The master realm never sends "required" nor "trusted devices": both are locked there. */
export function realmMfaPatch(before: MfaPolicies, d: RealmMfaDraft, system: boolean): RealmMfaBody {
  const body: RealmMfaBody = {};
  if (!system && d.required !== before.required_globally) body.required_globally = d.required;
  if (Number(d.maxAge) !== before.step_up_max_age_minutes) body.step_up_max_age_minutes = Number(d.maxAge);
  if (!system && d.trusted !== before.trusted_devices_enabled) body.trusted_devices_enabled = d.trusted;
  if (!system && d.trusted && Number(d.trustedDays) !== before.trusted_device_days)
    body.trusted_device_days = Number(d.trustedDays);
  return body;
}
