"use client";

import { Send } from "lucide-react";
import { useState } from "react";
import { useEditLock } from "@/components/console/drawer";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { TogglePill } from "@/components/ui/toggle-pill";
import { formatDateTime } from "@/lib/format";
import { NUMBERS, settingsDiff, type NumberKey } from "@/lib/settings-form";
import type { Settings } from "@/lib/types";
import { sendTestEmail, updateSettings } from "./actions";

export function SettingsForm({ realm, settings, writable }: { realm: string; settings: Settings; writable: boolean }) {
  const initial = Object.fromEntries(NUMBERS.map((k) => [k, String(settings[k])])) as Record<NumberKey, string>;
  const [form, setForm] = useState(initial);
  const [allowlist, setAllowlist] = useState((settings.ip_allowlist ?? []).join("\n"));
  const [notif, setNotif] = useState(settings.notification_email_enabled);
  const [suspicious, setSuspicious] = useState(settings.suspicious_login_email_enabled);
  const [remember, setRemember] = useState(settings.remember_me_enabled);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [to, setTo] = useState("");
  const { locked, banner } = useEditLock({ canWrite: writable, managedByConfig: settings.managed_by === "config" });
  const { run, pending } = useAction();
  const testMail = useAction(); // its own spinner, apart from "Save changes"
  const patch = settingsDiff(settings, form, allowlist, { notif, suspicious, remember });
  const dirty = Object.keys(patch).length > 0;

  const num = (k: NumberKey, label: string, hint?: string) => (
    <Field label={label} htmlFor={`s-${k}`} hint={hint} error={error?.field === k ? error.message : undefined}>
      <Input
        id={`s-${k}`}
        type="number"
        inputMode="numeric"
        value={form[k]}
        onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))}
        aria-invalid={error?.field === k || undefined}
      />
    </Field>
  );

  return (
    <div className="space-y-4">
      {banner}
      {error && !error.field && <Banner tone="danger">{error.message}</Banner>}
      <fieldset disabled={locked} className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardTitle>Password policy</CardTitle>
          <CardDescription>Passwords are hashed with Argon2id; these rules apply when one is chosen.</CardDescription>
          <div className="mt-4 space-y-4">
            {num(
              "min_password_length",
              "Minimum length",
              "8 at least. Length beats complexity rules (NIST SP 800-63B).",
            )}
            {num(
              "password_expiry_days",
              "Expiry (days, 0 = never)",
              "NIST advises against periodic changes: keep 0 unless a rule requires it.",
            )}
            {num("password_reset_ttl_minutes", "Reset link validity (minutes)", "5 to 1440.")}
          </div>
        </Card>
        <Card>
          <CardTitle>Session policy</CardTitle>
          <CardDescription>How long a sign-in lasts at the identity provider.</CardDescription>
          <div className="mt-4 space-y-4">
            {num("session_idle_minutes", "Idle timeout (minutes)")}
            {num("session_max_hours", "Maximum session duration (hours)")}
            <Toggle
              label="Keep me signed in"
              hint="Offer the option on the sign-in page: the session then survives a browser restart."
              checked={remember}
              onChange={setRemember}
              locked={locked}
            />
            {remember && (
              <>
                {num(
                  "remember_me_idle_days",
                  "Kept signed in: idle timeout (days)",
                  "The session ends after this many days without use.",
                )}
                {num(
                  "remember_me_max_days",
                  "Kept signed in: maximum duration (days)",
                  "30 at most is advised (NIST SP 800-63B, AAL1). 1 to 365.",
                )}
              </>
            )}
          </div>
        </Card>
        <Card>
          <CardTitle>Brute-force protection</CardTitle>
          <CardDescription>Accounts are locked after repeated failed sign-ins.</CardDescription>
          <div className="mt-4 space-y-4">
            {num("lockout_threshold", "Lockout threshold (failed attempts, 0 = off)")}
            {num("lockout_duration_minutes", "Lockout duration (minutes)")}
            <Field
              label="IP allowlist"
              htmlFor="s-ips"
              optional
              hint="One IP or CIDR per line. Stored for a later version: not enforced yet."
              error={error?.field === "ip_allowlist" ? error.message : undefined}
            >
              <Textarea
                id="s-ips"
                rows={3}
                className="font-mono text-[13px]"
                value={allowlist}
                onChange={(e) => setAllowlist(e.target.value)}
                placeholder="10.42.0.0/16"
              />
            </Field>
          </div>
        </Card>
        <Card>
          <CardTitle>Notifications</CardTitle>
          <CardDescription>Security e-mails sent to users of this realm.</CardDescription>
          <div className="mt-4 space-y-3">
            {!settings.email_enabled && (
              <Banner tone="warning">
                E-mail is not configured on the server (SMTP_HOST): nothing can be sent until it is.
              </Banner>
            )}
            <Toggle
              label="Security alerts"
              hint="Password changed, new factor, new device..."
              checked={notif}
              onChange={setNotif}
              locked={locked}
            />
            <Toggle
              label="Suspicious sign-in alerts"
              hint="Sign-in from an unusual place or device."
              checked={suspicious}
              onChange={setSuspicious}
              locked={locked}
            />
            {num(
              "key_rotation_grace_hours",
              "Default key rotation grace (hours)",
              "How long a rotated signing key stays published.",
            )}
          </div>
        </Card>
      </fieldset>
      <div className="flex flex-wrap items-center gap-3">
        <Button
          loading={pending}
          disabled={locked || pending || !dirty}
          onClick={async () => {
            setError(null);
            const r = await run(() => updateSettings(realm, patch), { quiet: true, success: "Settings saved" });
            if (!r.ok) setError({ field: r.field, message: r.message });
          }}
        >
          {pending ? "Saving…" : "Save changes"}
        </Button>
        {dirty && <span className="text-[12px] text-warning">Unsaved changes</span>}
        <span className="ml-auto text-[12px] text-text-muted">
          Last change {formatDateTime(settings.updated_at)}
          {settings.updated_by && ` by ${settings.updated_by}`}
        </span>
      </div>

      <Card>
        <CardTitle>Send a test e-mail</CardTitle>
        <CardDescription>Checks the server&apos;s SMTP settings end to end.</CardDescription>
        <form
          className="mt-4 flex flex-wrap items-end gap-2"
          onSubmit={async (e) => {
            e.preventDefault();
            await testMail.run(() => sendTestEmail(realm, to.trim()), {
              success: `Test e-mail sent to ${to.trim()}`,
              refresh: false,
            });
          }}
        >
          <Field label="Recipient" htmlFor="s-to" className="w-72">
            <Input
              id="s-to"
              type="email"
              required
              value={to}
              onChange={(e) => setTo(e.target.value)}
              disabled={!settings.email_enabled || locked}
            />
          </Field>
          <Button
            type="submit"
            variant="secondary"
            loading={testMail.pending}
            disabled={!settings.email_enabled || locked || !to.trim()}
          >
            {!testMail.pending && <Send className="size-3.5" />}
            Send test e-mail
          </Button>
        </form>
      </Card>
    </div>
  );
}

function Toggle({
  label,
  hint,
  checked,
  onChange,
  locked,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  locked: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-border px-4 py-3">
      <div>
        <p className="text-[14px] font-medium">{label}</p>
        <p className="text-[12px] text-text-muted">{hint}</p>
      </div>
      <TogglePill checked={checked} onCheckedChange={locked ? undefined : onChange} label={label} />
    </div>
  );
}
