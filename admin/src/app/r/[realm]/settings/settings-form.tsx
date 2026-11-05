"use client";

import { Send } from "lucide-react";
import { useEffect, useState } from "react";
import { useEditLock } from "@/components/console/drawer";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { TogglePill } from "@/components/ui/toggle-pill";
import { useT } from "@/i18n/client";
import { formatDateTime } from "@/lib/format";
import {
  fieldSection,
  MAIL_FIELDS,
  NUMBERS,
  settingsDiff,
  type MailForm,
  type NumberKey,
  type SettingsSection,
} from "@/lib/settings-form";
import type { Settings } from "@/lib/types";
import { sendTestEmail, updateSettings } from "./actions";

// One form across the four sub-pages (?tab=): only the cards change. The page
// is not remounted when just ?tab= changes, so what was typed on one sub-page
// is still there on the next, and "Save changes" sends it all.
/** Duration of the save bar's enter and exit animations (the class names below say duration-200). */
const BAR_MS = 200;

export function SettingsForm({
  realm,
  settings,
  writable,
  section,
  realmCard,
  infrastructure,
}: {
  realm: string;
  settings: Settings;
  writable: boolean;
  section: SettingsSection;
  /** The two read-only cards of the "general" section (Server Components). */
  realmCard?: React.ReactNode;
  infrastructure?: React.ReactNode;
}) {
  const { t, locale: uiLocale } = useT();
  const initial = Object.fromEntries(NUMBERS.map((k) => [k, String(settings[k])])) as Record<NumberKey, string>;
  const [form, setForm] = useState(initial);
  const [allowlist, setAllowlist] = useState((settings.ip_allowlist ?? []).join("\n"));
  const [notif, setNotif] = useState(settings.notification_email_enabled);
  const [suspicious, setSuspicious] = useState(settings.suspicious_login_email_enabled);
  const [remember, setRemember] = useState(settings.remember_me_enabled);
  const [locale, setLocale] = useState(settings.default_locale || "en");
  const [mail, setMail] = useState(Object.fromEntries(MAIL_FIELDS.map((k) => [k, settings[k] ?? ""])) as MailForm);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [to, setTo] = useState("");
  const { locked, banner } = useEditLock({ canWrite: writable, managedByConfig: settings.managed_by === "config" });
  const { run, pending } = useAction();
  const testMail = useAction(); // its own spinner, apart from "Save changes"
  const patch = settingsDiff(settings, form, allowlist, { notif, suspicious, remember }, locale, mail);
  const dirty = Object.keys(patch).length > 0;
  // The save bar slides up when there is something to save and slides back down
  // when there is not: it stays mounted while its exit animation plays.
  const showBar = dirty || pending;
  const [barMounted, setBarMounted] = useState(showBar);
  if (showBar && !barMounted) setBarMounted(true);
  useEffect(() => {
    if (showBar || !barMounted) return;
    const timer = setTimeout(() => setBarMounted(false), BAR_MS);
    return () => clearTimeout(timer);
  }, [showBar, barMounted]);
  const languages = settings.languages?.length ? settings.languages : [{ tag: "en", name: "English" }];
  // Next to its field when it shows here, otherwise at the top of the page.
  const errorOnField = !!error?.field && fieldSection(error.field) === section;

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

  const mailField = (
    k: keyof MailForm,
    label: string,
    hint: string,
    opts: { type?: string; placeholder?: string } = {},
  ) => (
    <Field label={label} htmlFor={`s-${k}`} optional hint={hint} error={error?.field === k ? error.message : undefined}>
      <Input
        id={`s-${k}`}
        type={opts.type ?? "text"}
        value={mail[k]}
        placeholder={opts.placeholder}
        onChange={(e) => setMail((m) => ({ ...m, [k]: e.target.value }))}
        aria-invalid={error?.field === k || undefined}
      />
    </Field>
  );
  const logoOk = /^https:\/\/\S+$/.test(mail.mail_logo_url.trim());

  return (
    <div className="space-y-4">
      {banner}
      {error && !errorOnField && <Banner tone="danger">{error.message}</Banner>}
      <fieldset disabled={locked} className="grid gap-4 lg:grid-cols-2">
        {section === "general" && (
          <>
            {realmCard}
            <Card>
              <CardTitle>{t("settings.language.title", "Language")}</CardTitle>
              <CardDescription>
                {t(
                  "settings.language.description",
                  "The language of the sign-in pages, the account console and the e-mails, for the users of this realm who did not choose one in their account console.",
                )}
              </CardDescription>
              <div className="mt-4 space-y-4">
                <Field
                  label={t("settings.language.default", "Default language")}
                  htmlFor="s-locale"
                  hint={t(
                    "settings.language.default_hint",
                    "English unless set. More languages: a translation file on the server (LOCALES_DIR).",
                  )}
                  error={error?.field === "default_locale" ? error.message : undefined}
                >
                  <NativeSelect
                    id="s-locale"
                    value={locale}
                    onChange={(e) => setLocale(e.target.value)}
                    wrapperClassName="max-w-xs"
                  >
                    {languages.map((l) => (
                      <option key={l.tag} value={l.tag} lang={l.tag}>
                        {l.name}
                      </option>
                    ))}
                  </NativeSelect>
                </Field>
              </div>
            </Card>
            {infrastructure && <div className="lg:col-span-2">{infrastructure}</div>}
          </>
        )}

        {section === "security" && (
          <>
            <Card>
              <CardTitle>{t("settings.password.title", "Password policy")}</CardTitle>
              <CardDescription>
                {t(
                  "settings.password.description",
                  "Passwords are hashed with Argon2id; these rules apply when one is chosen.",
                )}
              </CardDescription>
              <div className="mt-4 space-y-4">
                {num(
                  "min_password_length",
                  t("settings.password.min_length", "Minimum length"),
                  t(
                    "settings.password.min_length_hint",
                    "8 at least. Length beats complexity rules (NIST SP 800-63B).",
                  ),
                )}
                {num(
                  "password_expiry_days",
                  t("settings.password.expiry", "Expiry (days, 0 = never)"),
                  t(
                    "settings.password.expiry_hint",
                    "NIST advises against periodic changes: keep 0 unless a rule requires it.",
                  ),
                )}
                {num(
                  "password_reset_ttl_minutes",
                  t("settings.password.reset_ttl", "Reset link validity (minutes)"),
                  t("settings.password.reset_ttl_hint", "5 to 1440."),
                )}
                {num(
                  "invite_ttl_hours",
                  t("settings.password.invite_ttl", "Invitation link validity (hours)"),
                  t(
                    "settings.password.invite_ttl_hint",
                    "1 to 720. Applies to new invitations and resent activation links.",
                  ),
                )}
              </div>
            </Card>
            <div className="space-y-4">
              <Card>
                <CardTitle>{t("settings.lockout.title", "Brute-force protection")}</CardTitle>
                <CardDescription>
                  {t("settings.lockout.description", "Accounts are locked after repeated failed sign-ins.")}
                </CardDescription>
                <div className="mt-4 space-y-4">
                  {num(
                    "lockout_threshold",
                    t("settings.lockout.threshold", "Lockout threshold (failed attempts, 0 = off)"),
                  )}
                  {num("lockout_duration_minutes", t("settings.lockout.duration", "Lockout duration (minutes)"))}
                  <Field
                    label={t("settings.lockout.allowlist", "IP allowlist")}
                    htmlFor="s-ips"
                    optional
                    hint={t(
                      "settings.lockout.allowlist_hint",
                      "One IP or CIDR per line. Stored for a later version: not enforced yet.",
                    )}
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
                <CardTitle>{t("settings.rotation.title", "Signing key rotation")}</CardTitle>
                <CardDescription>
                  {t(
                    "settings.rotation.description",
                    "Applies when a key of this realm is rotated (Signing Keys tab or CLI).",
                  )}
                </CardDescription>
                <div className="mt-4 space-y-4">
                  {num(
                    "key_rotation_grace_hours",
                    t("settings.rotation.grace", "Default key rotation grace (hours)"),
                    t("settings.rotation.grace_hint", "How long a rotated signing key stays published."),
                  )}
                </div>
              </Card>
            </div>
          </>
        )}

        {section === "sessions" && (
          <>
            <Card>
              <CardTitle>{t("settings.session.title", "Session policy")}</CardTitle>
              <CardDescription>
                {t("settings.session.description", "How long a sign-in lasts at the identity provider.")}
              </CardDescription>
              <div className="mt-4 space-y-4">
                {num("session_idle_minutes", t("settings.session.idle", "Idle timeout (minutes)"))}
                {num("session_max_hours", t("settings.session.max", "Maximum session duration (hours)"))}
              </div>
            </Card>
            <Card>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <CardTitle>{t("settings.session.remember", "Keep me signed in")}</CardTitle>
                  <CardDescription>
                    {t(
                      "settings.session.remember_hint",
                      "Offer the option on the sign-in page: the session then survives a browser restart.",
                    )}
                  </CardDescription>
                </div>
                <TogglePill
                  checked={remember}
                  onCheckedChange={locked ? undefined : setRemember}
                  label={t("settings.session.remember", "Keep me signed in")}
                />
              </div>
              {remember && (
                <div className="mt-4 space-y-4">
                  {num(
                    "remember_me_idle_days",
                    t("settings.session.remember_idle", "Kept signed in: idle timeout (days)"),
                    t("settings.session.remember_idle_hint", "The session ends after this many days without use."),
                  )}
                  {num(
                    "remember_me_max_days",
                    t("settings.session.remember_max", "Kept signed in: maximum duration (days)"),
                    t("settings.session.remember_max_hint", "30 at most is advised (NIST SP 800-63B, AAL1). 1 to 365."),
                  )}
                </div>
              )}
            </Card>
          </>
        )}

        {section === "email" && (
          <>
            <Card>
              <CardTitle>{t("settings.notifications.title", "Notifications")}</CardTitle>
              <CardDescription>
                {t("settings.notifications.description", "Security e-mails sent to users of this realm.")}
              </CardDescription>
              <div className="mt-4 space-y-3">
                {!settings.email_enabled && (
                  <Banner tone="warning">
                    {t(
                      "settings.notifications.no_smtp",
                      "E-mail is not configured on the server (SMTP_HOST): nothing can be sent until it is.",
                    )}
                  </Banner>
                )}
                <Toggle
                  label={t("settings.notifications.alerts", "Security alerts")}
                  hint={t("settings.notifications.alerts_hint", "Password changed, new factor, new device...")}
                  checked={notif}
                  onChange={setNotif}
                  locked={locked}
                />
                <Toggle
                  label={t("settings.notifications.suspicious", "Suspicious sign-in alerts")}
                  hint={t("settings.notifications.suspicious_hint", "Sign-in from an unusual place or device.")}
                  checked={suspicious}
                  onChange={setSuspicious}
                  locked={locked}
                />
              </div>
            </Card>
            <Card>
              <CardTitle>{t("settings.mail.title", "E-mail sender")}</CardTitle>
              <CardDescription>
                {t(
                  "settings.mail.description",
                  "How the e-mails of this realm appear in the inbox. Empty fields keep the server's default sender.",
                )}
              </CardDescription>
              <div className="mt-4 space-y-4">
                {mailField(
                  "mail_from_name",
                  t("settings.mail.from_name", "Sender name"),
                  t("settings.mail.from_name_hint", 'Shown as the sender, for example "Acme Support".'),
                  { placeholder: "Acme Support" },
                )}
                {mailField(
                  "mail_from_address",
                  t("settings.mail.from_address", "Sender address"),
                  t(
                    "settings.mail.from_address_hint",
                    "The mail server must allow it (SPF/DKIM of its domain), or e-mails are rejected or land in spam.",
                  ),
                  { type: "email", placeholder: "no-reply@acme.example" },
                )}
                {mailField(
                  "mail_reply_to",
                  t("settings.mail.reply_to", "Reply-to address"),
                  t("settings.mail.reply_to_hint", "Where replies go. Without it, replies go to the sender address."),
                  { type: "email", placeholder: "support@acme.example" },
                )}
                {mailField(
                  "mail_logo_url",
                  t("settings.mail.logo", "Header image"),
                  t(
                    "settings.mail.logo_hint",
                    "An https:// address of a square image (shown at 28 px), in place of the product initial.",
                  ),
                  { type: "url", placeholder: "https://acme.example/logo.png" },
                )}
                {logoOk && (
                  // eslint-disable-next-line @next/next/no-img-element -- an arbitrary external address typed by the admin
                  <img
                    src={mail.mail_logo_url.trim()}
                    alt=""
                    width={28}
                    height={28}
                    className="size-7 rounded-md border border-border"
                  />
                )}
              </div>
            </Card>
            <Card className="lg:col-span-2">
              <CardTitle>{t("settings.test.title", "Send a test e-mail")}</CardTitle>
              <CardDescription>
                {t(
                  "settings.test.description",
                  "Checks the server's SMTP settings end to end, with the saved sender of this realm.",
                )}
              </CardDescription>
              <form
                className="mt-4 flex flex-wrap items-end gap-2"
                onSubmit={async (e) => {
                  e.preventDefault();
                  await testMail.run(() => sendTestEmail(realm, to.trim()), {
                    success: t("settings.test.sent", "Test e-mail sent to {to}", { to: to.trim() }),
                    refresh: false,
                  });
                }}
              >
                <Field label={t("settings.test.recipient", "Recipient")} htmlFor="s-to" className="w-72">
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
                  {t("settings.test.send", "Send test e-mail")}
                </Button>
              </form>
            </Card>
          </>
        )}
      </fieldset>
      {/* The save bar floats at the bottom of the window while something is
          changed (or being saved): the button is in reach wherever the page is scrolled. */}
      {barMounted && (
        <div
          role="region"
          aria-label={t("settings.unsaved", "Unsaved changes")}
          data-state={showBar ? "open" : "closed"}
          className="fill-mode-forwards motion-reduce:animate-none data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:slide-out-to-bottom-4 data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:slide-in-from-bottom-4 fixed bottom-6 left-1/2 z-40 flex w-max max-w-[calc(100%-2rem)] -translate-x-1/2 items-center gap-4 rounded-xl border border-border-strong bg-surface-alt py-2.5 pr-3 pl-5 shadow-[inset_0_1px_0_rgb(255_255_255/0.05),0_1px_2px_rgb(0_0_0/0.1),0_10px_24px_-10px_rgb(0_0_0/0.3)] duration-200"
        >
          <span className="text-[13px] font-medium text-warning">{t("settings.unsaved", "Unsaved changes")}</span>
          <Button
            loading={pending}
            disabled={locked || pending || !dirty}
            onClick={async () => {
              setError(null);
              const r = await run(() => updateSettings(realm, patch), {
                quiet: true,
                success: t("settings.saved", "Settings saved"),
              });
              if (!r.ok) setError({ field: r.field, message: r.message });
            }}
          >
            {pending ? t("common.saving", "Saving…") : t("settings.save", "Save changes")}
          </Button>
        </div>
      )}
      <div className="flex items-center">
        <span className="ml-auto text-[12px] text-text-muted">
          {settings.updated_by
            ? t("settings.last_change_by", "Last change {when} by {who}", {
                when: formatDateTime(settings.updated_at, uiLocale),
                who: settings.updated_by,
              })
            : t("settings.last_change", "Last change {when}", { when: formatDateTime(settings.updated_at, uiLocale) })}
        </span>
      </div>
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
