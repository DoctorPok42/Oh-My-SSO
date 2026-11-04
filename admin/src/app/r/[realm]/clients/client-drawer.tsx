"use client";

import { ChevronDown, Plus, RefreshCw } from "lucide-react";
import { useState } from "react";
import { ConfirmAction } from "@/components/console/confirm";
import { Drawer, useDrawerUrl, useEditLock } from "@/components/console/drawer";
import { SuspendLink } from "@/components/console/suspend-link";
import { SecretOnceDialog } from "@/components/console/secret-once";
import { useStepUp } from "@/components/console/step-up";
import { StatusBadge } from "@/components/console/status-badge";
import { useAction } from "@/components/console/use-action";
import { Badge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CheckboxField } from "@/components/ui/checkbox";
import { ChipSelect } from "@/components/ui/chip-select";
import { CopyField } from "@/components/ui/copy-button";
import { Field } from "@/components/ui/field";
import { Input, Textarea } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Segmented } from "@/components/ui/segmented";
import { TogglePill } from "@/components/ui/toggle-pill";
import { useT } from "@/i18n/client";
import { clientBody, draftFromClient, emptyDraft, type ClientDraft } from "@/lib/client-form";
import { formatDate } from "@/lib/format";
import { MFA_METHOD_LABELS, NAME_ID_FORMATS, STANDARD_SCOPES } from "@/lib/labels";
import type { Access, Client, ClientScope, ClientSummary } from "@/lib/types";
import {
  addCertificate,
  createClient,
  deleteClient,
  removeCertificate,
  rotateClientSecret,
  updateClient,
} from "./actions";

type Secret = { title: string; items: { label: string; value: string }[] } | null;

export function NewClientButton() {
  const { openNew } = useDrawerUrl();
  const stepUp = useStepUp();
  const { t } = useT();
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      {t("clients.new", "New client")}
    </Button>
  );
}

export function ClientRowActions({
  realm,
  client,
  writable,
}: Readonly<{
  realm: string;
  client: ClientSummary;
  writable: boolean;
}>) {
  const { openEdit } = useDrawerUrl();
  const { t } = useT();
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(client.id)}>
        {writable && client.managed_by !== "config" ? t("common.edit", "Edit") : t("common.view", "View")}
      </Button>
      {writable && client.managed_by !== "config" && (
        <ConfirmAction
          trigger={t("common.delete", "Delete")}
          title={t("clients.delete.title", "Delete {name}?", { name: client.name })}
          description={t(
            "clients.delete.text",
            "Users can no longer sign in to this application, and every token it holds is revoked. This cannot be undone.",
          )}
          confirmLabel={t("clients.delete.confirm", "Delete client")}
          success={t("clients.delete.done", "Client deleted")}
          action={() => deleteClient(realm, client.id)}
        />
      )}
    </div>
  );
}

export function ClientDrawer({
  realm,
  mode,
  client,
  writable,
  roles,
  groups,
  scopes,
  mfaMethods,
  canReadAccess,
  canSuspend = false,
}: Readonly<{
  realm: string;
  mode: "create" | "edit" | null;
  client: Client | null;
  writable: boolean;
  roles: Access[];
  groups: Access[];
  scopes: ClientScope[];
  mfaMethods: string[];
  canReadAccess: boolean;
  /** timeout:write: the footer offers "Suspend…" (Timeouts page). */
  canSuspend?: boolean;
}>) {
  const { close, openEdit } = useDrawerUrl();
  const { run, pending } = useAction();
  const { t, tm, locale } = useT();
  const [draft, setDraft] = useState<ClientDraft>(() => (client ? draftFromClient(client) : emptyDraft()));
  const [secret, setSecret] = useState<Secret>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [fieldError, setFieldError] = useState<{ field?: string; message: string } | null>(null);
  const managed = client?.managed_by === "config";
  const intent = mode === "create" ? "new=1" : client ? `edit=${client.id}` : undefined;
  const { locked, banner } = useEditLock({ canWrite: writable, managedByConfig: managed, intent });

  // A new item opened: start from its values.
  const key = mode === "create" ? "new" : (client?.id ?? "");
  const [lastKey, setLastKey] = useState(key);
  if (key !== lastKey) {
    setLastKey(key);
    setDraft(client ? draftFromClient(client) : emptyDraft());
    setFieldError(null);
  }

  const set = <K extends keyof ClientDraft>(k: K, v: ClientDraft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const isOidc = draft.protocol === "oidc";
  const scopeChoices = scopes.filter((s) => s.protocol === "both" || s.protocol === draft.protocol);

  async function save() {
    setFieldError(null);
    if (mode === "create") {
      const r = await run(() => createClient(realm, clientBody(draft, "create")), { quiet: true, intent });
      if (!r.ok) return setFieldError({ field: r.field, message: r.message });
      if (r.data.secret) {
        setSecret({
          title: t("clients.ready", "{name} is ready", { name: r.data.client.name }),
          items: [
            { label: t("clients.field.client_id", "Client ID"), value: r.data.client.client_id ?? "" },
            { label: t("clients.field.secret", "Client secret"), value: r.data.secret },
          ],
        });
      }
      openEdit(r.data.client.id);
      return;
    }
    if (!client) return;
    const r = await run(() => updateClient(realm, client.id, clientBody(draft, "update")), {
      quiet: true,
      success: t("clients.saved", "Client saved"),
      intent,
    });
    if (!r.ok) setFieldError({ field: r.field, message: r.message });
  }

  const err = (field: string) => (fieldError?.field === field ? fieldError.message : undefined);

  return (
    <>
      <Drawer
        open={mode !== null}
        onClose={close}
        width="lg"
        title={mode === "create" ? t("clients.new", "New client") : (client?.name ?? t("clients.client", "Client"))}
        description={
          mode === "create"
            ? t("clients.new_description", "An application that signs its users in with this realm.")
            : client && (
                <span className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={client.status} />
                  {managed && <Badge tone="neutral">{t("status.managed_by_config", "Managed by config")}</Badge>}
                  <span>
                    {t("common.created_on", "Created {date}", { date: formatDate(client.created_at, locale) })}
                  </span>
                </span>
              )
        }
        footer={
          <>
            <Button onClick={save} loading={pending} disabled={locked || pending}>
              {pending
                ? t("common.saving", "Saving…")
                : mode === "create"
                  ? t("clients.create", "Create client")
                  : t("common.save", "Save")}
            </Button>
            <Button variant="secondary" onClick={close}>
              {t("common.cancel", "Cancel")}
            </Button>
            {mode === "edit" && client && canSuspend && client.client_id !== "sso-admin" && (
              <SuspendLink className="ml-auto" realm={realm} type="client" id={client.id} name={client.name} />
            )}
          </>
        }
      >
        {banner}
        {fieldError && !fieldError.field && <Banner tone="danger">{fieldError.message}</Banner>}

        <fieldset disabled={locked} className="space-y-5">
          <Field label={t("clients.field.name", "Name")} htmlFor="c-name" error={err("name")}>
            <Input id="c-name" value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder="Payroll" />
          </Field>

          <div className="flex flex-wrap items-end justify-between gap-4">
            <Field label={t("clients.field.protocol", "Protocol")}>
              <Segmented
                label={t("clients.field.protocol", "Protocol")}
                value={draft.protocol}
                disabled={mode !== "create" || locked}
                onChange={(p) => setDraft((d) => ({ ...d, protocol: p, scopes: [] }))}
                options={[
                  { value: "oidc", label: "OIDC" },
                  { value: "saml2", label: "SAML 2.0" },
                ]}
              />
            </Field>
            <Field label={t("clients.field.status", "Status")}>
              <TogglePill
                checked={draft.active}
                onCheckedChange={locked ? undefined : (v) => set("active", v)}
                onLabel={t("status.active", "Active")}
                offLabel={t("status.disabled", "Disabled")}
                label={t("status.active", "Active")}
              />
            </Field>
          </div>

          {isOidc ? (
            <OidcFields draft={draft} set={set} mode={mode} client={client} err={err} />
          ) : (
            <SamlFields draft={draft} set={set} mode={mode} err={err} />
          )}

          <Field
            label={t("clients.field.scopes", "Client scopes")}
            hint={t(
              "clients.field.scopes_hint",
              "Extra claim sets this client receives. Required: always granted; optional: only when asked for.",
            )}
          >
            {scopeChoices.length === 0 ? (
              <p className="text-[13px] text-text-muted">
                {t("clients.no_scope", "No client scope for this protocol yet.")}
              </p>
            ) : (
              <div className="divide-y divide-border rounded-lg border border-border">
                {scopeChoices.map((s) => {
                  const chosen = draft.scopes.find((c) => c.id === s.id);
                  return (
                    <div key={s.id} className="flex items-center justify-between gap-3 px-3 py-2">
                      <CheckboxField
                        id={`scope-${s.id}`}
                        label={s.name}
                        checked={!!chosen}
                        onCheckedChange={(v) =>
                          set(
                            "scopes",
                            v
                              ? [...draft.scopes, { id: s.id, required: s.is_default }]
                              : draft.scopes.filter((c) => c.id !== s.id),
                          )
                        }
                      />
                      {chosen && (
                        <TogglePill
                          checked={chosen.required}
                          onLabel={t("clients.scope.required", "Required")}
                          offLabel={t("clients.scope.optional", "Optional")}
                          label={t("clients.scope.required_label", "{name} required", { name: s.name })}
                          onCheckedChange={
                            locked
                              ? undefined
                              : (v) =>
                                  set(
                                    "scopes",
                                    draft.scopes.map((c) => (c.id === s.id ? { ...c, required: v } : c)),
                                  )
                          }
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Field>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-[13px] font-semibold">{t("clients.access.title", "Access")}</p>
            {!canReadAccess && (
              <p className="text-[12px] text-text-muted">
                {t("clients.access.hidden", "Roles and groups are hidden: you may not read them.")}
              </p>
            )}
            <Field
              label={t("clients.access.roles", "Allowed roles")}
              hint={t("clients.access.roles_hint", "None selected: every role may sign in.")}
            >
              <ChipSelect
                label={t("clients.access.roles", "Allowed roles")}
                options={roles}
                value={draft.roleIds}
                onChange={(v) => set("roleIds", v)}
                disabled={locked}
                empty={t("clients.access.no_role", "No role in this realm.")}
              />
            </Field>
            <Field
              label={t("clients.access.groups", "Allowed groups")}
              hint={t("clients.access.groups_hint", "None selected: every group may sign in.")}
            >
              <ChipSelect
                label={t("clients.access.groups", "Allowed groups")}
                options={groups}
                value={draft.groupIds}
                onChange={(v) => set("groupIds", v)}
                disabled={locked}
                empty={t("clients.access.no_group", "No group in this realm.")}
              />
            </Field>
            <CheckboxField
              id="c-consent"
              label={t("clients.consent", "Show the consent screen")}
              hint={t(
                "clients.consent_hint",
                "Users approve what this application receives the first time (and when it asks for more).",
              )}
              checked={draft.requireConsent}
              onCheckedChange={(v) => set("requireConsent", v === true)}
            />
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-[13px] font-semibold">{t("clients.mfa.title", "Multi-factor authentication")}</p>
            <Field
              label={t("clients.mfa.policy", "Policy")}
              hint={t("clients.mfa.policy_hint", "The strictest of the realm, client and role policies applies.")}
            >
              <NativeSelect
                value={draft.mfaPolicy}
                onChange={(e) => set("mfaPolicy", e.target.value as ClientDraft["mfaPolicy"])}
              >
                <option value="inherit">{t("clients.mfa.inherit", "Inherit (realm and role policies)")}</option>
                <option value="required">{t("clients.mfa.required", "Always require a second factor")}</option>
              </NativeSelect>
            </Field>
            <Field
              label={t("clients.mfa.methods", "Accepted methods")}
              hint={t("clients.mfa.methods_hint", "None selected: any enrolled method.")}
            >
              <ChipSelect
                label={t("clients.mfa.methods_label", "Accepted MFA methods")}
                options={mfaMethods.map((id) => {
                  const label = MFA_METHOD_LABELS[id];
                  return { id, name: label ? tm(label) : id };
                })}
                value={draft.mfaMethods}
                onChange={(v) => set("mfaMethods", v)}
                disabled={locked}
              />
            </Field>
          </div>
        </fieldset>

        {!isOidc && (
          <button
            type="button"
            onClick={() => setShowAdvanced((v) => !v)}
            className="flex items-center gap-1 text-[13px] font-medium text-accent"
            aria-expanded={showAdvanced}
          >
            <ChevronDown className={showAdvanced ? "size-4 rotate-180" : "size-4"} />
            {t("clients.saml.advanced", "Advanced SAML settings")}
          </button>
        )}
        {!isOidc && showAdvanced && (
          <fieldset disabled={locked}>
            <SamlAdvanced draft={draft} set={set} />
          </fieldset>
        )}

        {mode === "edit" && client && (
          <EditOnlySections
            realm={realm}
            client={client}
            locked={locked}
            onSecret={(value) =>
              setSecret({
                title: t("clients.secret.new", "New client secret"),
                items: [
                  { label: t("clients.field.client_id", "Client ID"), value: client.client_id ?? "" },
                  { label: t("clients.field.secret", "Client secret"), value },
                ],
              })
            }
          />
        )}
      </Drawer>

      <SecretOnceDialog
        open={!!secret}
        title={secret?.title ?? ""}
        description={t("clients.secret.configure", "Configure the application with these values.")}
        items={secret?.items ?? []}
        onDone={() => setSecret(null)}
      />
    </>
  );
}

type SetFn = <K extends keyof ClientDraft>(k: K, v: ClientDraft[K]) => void;

function OidcFields({
  draft,
  set,
  mode,
  client,
  err,
}: Readonly<{
  draft: ClientDraft;
  set: SetFn;
  mode: "create" | "edit" | null;
  client: Client | null;
  err: (f: string) => string | undefined;
}>) {
  const { t } = useT();
  return (
    <>
      <Field
        label={t("clients.field.client_id", "Client ID")}
        htmlFor="c-client-id"
        optional={mode === "create"}
        hint={
          mode === "create" ? t("clients.field.client_id_hint", "Leave empty to derive it from the name.") : undefined
        }
        error={err("client_id")}
      >
        {mode === "create" ? (
          <Input
            id="c-client-id"
            className="font-mono"
            value={draft.clientId}
            onChange={(e) => set("clientId", e.target.value)}
            placeholder="payroll"
          />
        ) : (
          <CopyField value={client?.client_id ?? ""} />
        )}
      </Field>

      <Field label={t("clients.field.type", "Client type")}>
        <Segmented
          label={t("clients.field.type", "Client type")}
          value={draft.isPublic ? "public" : "confidential"}
          disabled={mode !== "create"}
          onChange={(v) => set("isPublic", v === "public")}
          options={[
            { value: "confidential", label: t("clients.type.confidential", "Confidential (server)") },
            { value: "public", label: t("clients.type.public", "Public (SPA, mobile)") },
          ]}
        />
        <p className="mt-1.5 text-[12px] text-text-muted">
          {draft.isPublic
            ? t("clients.type.public_hint", "No secret: a browser or phone app cannot keep one. PKCE is mandatory.")
            : t("clients.type.confidential_hint", "Has a secret, kept on the application's server.")}
        </p>
      </Field>

      <Field
        label={t("clients.field.redirect_uris", "Redirect URIs")}
        htmlFor="c-redirect"
        hint={t(
          "clients.field.redirect_uris_hint",
          "One per line, exact match (no wildcard). https, or http on localhost.",
        )}
        error={err("redirect_uris")}
      >
        <Textarea
          id="c-redirect"
          className="font-mono text-[13px]"
          rows={3}
          value={draft.redirectUris}
          onChange={(e) => set("redirectUris", e.target.value)}
          placeholder="https://payroll.example.com/auth/callback"
        />
      </Field>
      <Field
        label={t("clients.field.logout_uris", "Post-logout redirect URIs")}
        htmlFor="c-logout"
        optional
        hint={t("clients.field.logout_uris_hint", "Where users may land after signing out (one per line).")}
        error={err("post_logout_redirect_uris")}
      >
        <Textarea
          id="c-logout"
          className="font-mono text-[13px]"
          rows={2}
          value={draft.postLogoutUris}
          onChange={(e) => set("postLogoutUris", e.target.value)}
        />
      </Field>

      <Field
        label={t("clients.field.standard_scopes", "Standard scopes")}
        hint={t(
          "clients.field.standard_scopes_hint",
          "openid is always on: it makes the request an OpenID Connect one.",
        )}
      >
        <ChipSelect
          label={t("clients.field.standard_scopes", "Standard scopes")}
          options={STANDARD_SCOPES.map((s) => ({ id: s, name: s }))}
          value={draft.standardScopes}
          onChange={(v) => set("standardScopes", v.includes("openid") ? v : ["openid", ...v])}
        />
      </Field>

      {!draft.isPublic && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("clients.field.auth_method", "Token endpoint auth method")} htmlFor="c-auth">
            <NativeSelect id="c-auth" value={draft.authMethod} onChange={(e) => set("authMethod", e.target.value)}>
              <option value="client_secret_basic">client_secret_basic</option>
              <option value="client_secret_post">client_secret_post</option>
            </NativeSelect>
          </Field>
          <div className="flex items-end pb-2.5">
            <CheckboxField
              id="c-pkce"
              label={t("clients.field.pkce", "Require PKCE")}
              checked={draft.requirePkce}
              onCheckedChange={(v) => set("requirePkce", v === true)}
            />
          </div>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        <Field
          label={t("clients.field.access_ttl", "Access token (min)")}
          htmlFor="c-at"
          hint={t("clients.field.ttl_hint", "Empty: default")}
          error={err("access_token_ttl")}
        >
          <Input
            id="c-at"
            inputMode="decimal"
            value={draft.accessTtlMinutes}
            onChange={(e) => set("accessTtlMinutes", e.target.value)}
          />
        </Field>
        <Field
          label={t("clients.field.id_ttl", "ID token (min)")}
          htmlFor="c-it"
          hint={t("clients.field.ttl_hint", "Empty: default")}
          error={err("id_token_ttl")}
        >
          <Input
            id="c-it"
            inputMode="decimal"
            value={draft.idTtlMinutes}
            onChange={(e) => set("idTtlMinutes", e.target.value)}
          />
        </Field>
        <Field
          label={t("clients.field.refresh_ttl", "Refresh token (days)")}
          htmlFor="c-rt"
          hint={t("clients.field.ttl_hint", "Empty: default")}
          error={err("refresh_token_ttl")}
        >
          <Input
            id="c-rt"
            inputMode="decimal"
            value={draft.refreshTtlDays}
            onChange={(e) => set("refreshTtlDays", e.target.value)}
          />
        </Field>
      </div>
    </>
  );
}

function SamlFields({
  draft,
  set,
  mode,
  err,
}: Readonly<{
  draft: ClientDraft;
  set: SetFn;
  mode: "create" | "edit" | null;
  err: (f: string) => string | undefined;
}>) {
  const { t, tm } = useT();
  return (
    <>
      <Field
        label={t("clients.field.entity_id", "Entity ID")}
        htmlFor="c-entity"
        hint={t("clients.field.entity_id_hint", "The service provider's identifier, from its metadata.")}
        error={err("entity_id")}
      >
        <Input
          id="c-entity"
          className="font-mono text-[13px]"
          value={draft.entityId}
          onChange={(e) => set("entityId", e.target.value)}
          placeholder="https://sp.example.com/saml/metadata"
        />
      </Field>
      <Field
        label={t("clients.field.acs", "ACS URL")}
        htmlFor="c-acs"
        hint={t("clients.field.acs_hint", "Assertion Consumer Service: where the IdP posts the response.")}
        error={err("acs_url")}
      >
        <Input
          id="c-acs"
          className="font-mono text-[13px]"
          value={draft.acsUrl}
          onChange={(e) => set("acsUrl", e.target.value)}
          placeholder="https://sp.example.com/saml/acs"
        />
      </Field>
      <Field label={t("clients.field.nameid", "NameID format")} htmlFor="c-nameid" error={err("name_id_format")}>
        <NativeSelect id="c-nameid" value={draft.nameIdFormat} onChange={(e) => set("nameIdFormat", e.target.value)}>
          {NAME_ID_FORMATS.map((f) => (
            <option key={f.value} value={f.value}>
              {tm(f.label)}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {mode === "create" && (
        <>
          <CheckboxField
            id="c-pairwise"
            label={t("clients.field.pairwise", "Pairwise identifier")}
            hint={t(
              "clients.field.pairwise_hint",
              "This service provider gets its own persistent NameID per user: it cannot be matched with other providers.",
            )}
            checked={draft.pairwise}
            onCheckedChange={(v) => set("pairwise", v === true)}
          />
          <Field
            label={t("clients.field.certificate", "Signing certificate (PEM)")}
            htmlFor="c-cert"
            optional
            hint={t(
              "clients.field.certificate_hint",
              "The service provider's certificate, to verify its signed requests. More can be added later (rotation).",
            )}
            error={err("certificates")}
          >
            <Textarea
              id="c-cert"
              className="font-mono text-[12px]"
              rows={4}
              value={draft.certificatePem}
              onChange={(e) => set("certificatePem", e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
          </Field>
        </>
      )}
    </>
  );
}

function SamlAdvanced({ draft, set }: Readonly<{ draft: ClientDraft; set: SetFn }>) {
  const { t } = useT();
  return (
    <div className="space-y-4 rounded-lg border border-border p-4">
      <Field
        label={t("clients.saml.slo", "SLO URL")}
        htmlFor="c-slo"
        optional
        hint={t("clients.saml.slo_hint", "Single Logout endpoint of the service provider.")}
      >
        <Input
          id="c-slo"
          className="font-mono text-[13px]"
          value={draft.sloUrl}
          onChange={(e) => set("sloUrl", e.target.value)}
        />
      </Field>
      <Field label={t("clients.saml.relay_state", "Default RelayState")} htmlFor="c-relay" optional>
        <Input id="c-relay" value={draft.relayState} onChange={(e) => set("relayState", e.target.value)} />
      </Field>
      <div className="flex flex-wrap gap-6 text-[13px]">
        <span className="flex items-center gap-2">
          {t("clients.saml.assertion_signed", "Assertion signed")}{" "}
          <TogglePill
            checked
            onLabel={t("clients.saml.always", "Always")}
            offLabel={t("common.no", "No")}
            label={t("clients.saml.assertion_signed", "Assertion signed")}
          />
        </span>
        <span className="flex items-center gap-2">
          {t("clients.saml.response_signed", "Response signed")}
          <TogglePill
            checked={draft.wantResponseSigned}
            onCheckedChange={(v) => set("wantResponseSigned", v)}
            onLabel={t("common.yes", "Yes")}
            offLabel={t("common.no", "No")}
            label={t("clients.saml.response_signed", "Response signed")}
          />
        </span>
      </div>
    </div>
  );
}

/** Secret rotation and certificates: immediate actions, outside Save. */
function EditOnlySections({
  realm,
  client,
  locked,
  onSecret,
}: Readonly<{
  realm: string;
  client: Client;
  locked: boolean;
  onSecret: (secret: string) => void;
}>) {
  const { run, pending } = useAction();
  const { t, locale } = useT();
  const [pem, setPem] = useState("");
  const [notBefore, setNotBefore] = useState("");
  const [notAfter, setNotAfter] = useState("");
  const [adding, setAdding] = useState(false);

  return (
    <div className="space-y-5 border-t border-border pt-5">
      {client.oidc?.client_type === "confidential" && (
        <Field
          label={t("clients.field.secret", "Client secret")}
          hint={t(
            "clients.secret.hint",
            "Stored hashed: it cannot be shown again. Regenerate it if it was lost or leaked.",
          )}
        >
          <div className="flex items-center gap-3">
            <code className="flex-1 rounded-sm border border-border bg-surface-alt px-3 py-2 font-mono text-[13px] text-text-muted">
              ••••••••••••••••••••
            </code>
            <ConfirmAction
              trigger={
                <>
                  <RefreshCw className="size-3.5" />
                  {t("clients.secret.regenerate", "Regenerate")}
                </>
              }
              size="sm"
              variant="secondary"
              disabled={locked}
              title={t("clients.secret.regenerate_title", "Regenerate the client secret?")}
              description={t(
                "clients.secret.regenerate_text",
                "The current secret stops working at once: the application fails until it is configured with the new one.",
              )}
              confirmLabel={t("clients.secret.regenerate_confirm", "Regenerate secret")}
              action={() => rotateClientSecret(realm, client.id)}
              onDone={(d) => onSecret(d.secret)}
            />
          </div>
        </Field>
      )}

      {client.saml && (
        <div>
          <div className="mb-2 flex items-center justify-between">
            <p className="text-[13px] font-semibold text-text-secondary">{t("clients.certs.title", "Certificates")}</p>
            {!locked && !adding && (
              <Button size="xs" variant="secondary" onClick={() => setAdding(true)}>
                <Plus className="size-3.5" />
                {t("clients.certs.add_rotate", "Add (rotate)")}
              </Button>
            )}
          </div>
          <div className="space-y-2">
            {client.saml.certificates.length === 0 && (
              <p className="text-[13px] text-text-muted">
                {t("clients.certs.none", "No certificate: signed requests from this provider are refused.")}
              </p>
            )}
            {client.saml.certificates.map((c) => (
              <div key={c.fingerprint} className="rounded-lg border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <code className="truncate font-mono text-[12px]" title={c.fingerprint}>
                    {c.fingerprint.slice(0, 32)}…
                  </code>
                  <StatusBadge status={c.status} />
                </div>
                <p className="mt-1 truncate text-[12px] text-text-muted">{c.subject}</p>
                <div className="mt-1 flex items-center justify-between text-[12px] text-text-muted">
                  <span>
                    {t("clients.certs.valid", "Valid {from} → {to}", {
                      from: formatDate(c.not_before ?? undefined, locale),
                      to: formatDate(c.not_after ?? c.expires_at, locale),
                    })}
                  </span>
                  {!locked && client.saml!.certificates.length > 1 && (
                    <ConfirmAction
                      trigger={t("clients.certs.retire", "Retire")}
                      title={t("clients.certs.retire_title", "Retire this certificate?")}
                      description={t("clients.certs.retire_text", "Requests signed with it are refused from now on.")}
                      confirmLabel={t("clients.certs.retire", "Retire")}
                      action={() => removeCertificate(realm, client.id, c.fingerprint)}
                      success={t("clients.certs.retired", "Certificate retired")}
                    />
                  )}
                </div>
              </div>
            ))}
          </div>
          {adding && (
            <div className="mt-3 space-y-3 rounded-lg border border-border p-3">
              <Field label={t("clients.certs.new", "New certificate (PEM)")} htmlFor="cert-pem">
                <Textarea
                  id="cert-pem"
                  className="font-mono text-[12px]"
                  rows={4}
                  value={pem}
                  onChange={(e) => setPem(e.target.value)}
                />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label={t("clients.certs.valid_from", "Valid from")} htmlFor="cert-nb" optional>
                  <Input id="cert-nb" type="date" value={notBefore} onChange={(e) => setNotBefore(e.target.value)} />
                </Field>
                <Field label={t("clients.certs.valid_until", "Valid until")} htmlFor="cert-na" optional>
                  <Input id="cert-na" type="date" value={notAfter} onChange={(e) => setNotAfter(e.target.value)} />
                </Field>
              </div>
              <p className="text-[12px] text-text-muted">
                {t(
                  "clients.certs.rotation",
                  "Rotation: add the new certificate before the provider starts using it; retire the old one afterwards.",
                )}
              </p>
              <div className="flex gap-2">
                <Button
                  size="xs"
                  loading={pending}
                  disabled={pending || !pem.trim()}
                  onClick={async () => {
                    const r = await run(
                      () =>
                        addCertificate(realm, client.id, {
                          pem: pem.trim(),
                          not_before: notBefore ? new Date(notBefore).toISOString() : null,
                          not_after: notAfter ? new Date(notAfter).toISOString() : null,
                        }),
                      { success: t("clients.certs.added", "Certificate added") },
                    );
                    if (r.ok) {
                      setAdding(false);
                      setPem("");
                      setNotBefore("");
                      setNotAfter("");
                    }
                  }}
                >
                  {t("clients.certs.add", "Add certificate")}
                </Button>
                <Button size="xs" variant="secondary" onClick={() => setAdding(false)}>
                  {t("common.cancel", "Cancel")}
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {client.attribute_mappings && Object.keys(client.attribute_mappings).length > 0 && (
        <Field
          label={t("clients.mappings", "Attribute mappings")}
          hint={t("clients.mappings_hint", "Set by the configuration file or the CLI; read-only here.")}
        >
          <pre className="overflow-x-auto rounded-lg border border-border bg-surface-alt p-3 font-mono text-[12px]">
            {JSON.stringify(client.attribute_mappings, null, 2)}
          </pre>
        </Field>
      )}
    </div>
  );
}
