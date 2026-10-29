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
  return (
    <Button onClick={() => stepUp.ensure(openNew, "new=1")}>
      <Plus />
      New client
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
  return (
    <div className="flex justify-end gap-2">
      <Button variant="secondary" size="xs" onClick={() => openEdit(client.id)}>
        {writable && client.managed_by !== "config" ? "Edit" : "View"}
      </Button>
      {writable && client.managed_by !== "config" && (
        <ConfirmAction
          trigger="Delete"
          title={`Delete ${client.name}?`}
          description={
            <>
              Users can no longer sign in to this application, and every token it holds is revoked. This cannot be
              undone.
            </>
          }
          confirmLabel="Delete client"
          success="Client deleted"
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
          title: `${r.data.client.name} is ready`,
          items: [
            { label: "Client ID", value: r.data.client.client_id ?? "" },
            { label: "Client secret", value: r.data.secret },
          ],
        });
      }
      openEdit(r.data.client.id);
      return;
    }
    if (!client) return;
    const r = await run(() => updateClient(realm, client.id, clientBody(draft, "update")), {
      quiet: true,
      success: "Client saved",
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
        title={mode === "create" ? "New client" : (client?.name ?? "Client")}
        description={
          mode === "create"
            ? "An application that signs its users in with this realm."
            : client && (
                <span className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={client.status} />
                  {managed && <Badge tone="neutral">Managed by config</Badge>}
                  <span>Created {formatDate(client.created_at)}</span>
                </span>
              )
        }
        footer={
          <>
            <Button onClick={save} loading={pending} disabled={locked || pending}>
              {pending ? "Saving…" : mode === "create" ? "Create client" : "Save"}
            </Button>
            <Button variant="secondary" onClick={close}>
              Cancel
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
          <Field label="Name" htmlFor="c-name" error={err("name")}>
            <Input id="c-name" value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder="Payroll" />
          </Field>

          <div className="flex flex-wrap items-end justify-between gap-4">
            <Field label="Protocol">
              <Segmented
                label="Protocol"
                value={draft.protocol}
                disabled={mode !== "create" || locked}
                onChange={(p) => setDraft((d) => ({ ...d, protocol: p, scopes: [] }))}
                options={[
                  { value: "oidc", label: "OIDC" },
                  { value: "saml2", label: "SAML 2.0" },
                ]}
              />
            </Field>
            <Field label="Status">
              <TogglePill
                checked={draft.active}
                onCheckedChange={locked ? undefined : (v) => set("active", v)}
                onLabel="Active"
                offLabel="Disabled"
                label="Active"
              />
            </Field>
          </div>

          {isOidc ? (
            <OidcFields draft={draft} set={set} mode={mode} client={client} err={err} />
          ) : (
            <SamlFields draft={draft} set={set} mode={mode} err={err} />
          )}

          <Field
            label="Client scopes"
            hint="Extra claim sets this client receives. Required: always granted; optional: only when asked for."
          >
            {scopeChoices.length === 0 ? (
              <p className="text-[13px] text-text-muted">No client scope for this protocol yet.</p>
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
                          onLabel="Required"
                          offLabel="Optional"
                          label={`${s.name} required`}
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
            <p className="text-[13px] font-semibold">Access</p>
            {!canReadAccess && (
              <p className="text-[12px] text-text-muted">Roles and groups are hidden: you may not read them.</p>
            )}
            <Field label="Allowed roles" hint="None selected: every role may sign in.">
              <ChipSelect
                label="Allowed roles"
                options={roles}
                value={draft.roleIds}
                onChange={(v) => set("roleIds", v)}
                disabled={locked}
                empty="No role in this realm."
              />
            </Field>
            <Field label="Allowed groups" hint="None selected: every group may sign in.">
              <ChipSelect
                label="Allowed groups"
                options={groups}
                value={draft.groupIds}
                onChange={(v) => set("groupIds", v)}
                disabled={locked}
                empty="No group in this realm."
              />
            </Field>
            <CheckboxField
              id="c-consent"
              label="Show the consent screen"
              hint="Users approve what this application receives the first time (and when it asks for more)."
              checked={draft.requireConsent}
              onCheckedChange={(v) => set("requireConsent", v === true)}
            />
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-[13px] font-semibold">Multi-factor authentication</p>
            <Field label="Policy" hint="The strictest of the realm, client and role policies applies.">
              <NativeSelect
                value={draft.mfaPolicy}
                onChange={(e) => set("mfaPolicy", e.target.value as ClientDraft["mfaPolicy"])}
              >
                <option value="inherit">Inherit (realm and role policies)</option>
                <option value="required">Always require a second factor</option>
              </NativeSelect>
            </Field>
            <Field label="Accepted methods" hint="None selected: any enrolled method.">
              <ChipSelect
                label="Accepted MFA methods"
                options={mfaMethods.map((m) => ({ id: m, name: MFA_METHOD_LABELS[m] ?? m }))}
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
            Advanced SAML settings
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
                title: "New client secret",
                items: [
                  { label: "Client ID", value: client.client_id ?? "" },
                  { label: "Client secret", value },
                ],
              })
            }
          />
        )}
      </Drawer>

      <SecretOnceDialog
        open={!!secret}
        title={secret?.title ?? ""}
        description="Configure the application with these values."
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
  return (
    <>
      <Field
        label="Client ID"
        htmlFor="c-client-id"
        optional={mode === "create"}
        hint={mode === "create" ? "Leave empty to derive it from the name." : undefined}
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

      <Field label="Client type">
        <Segmented
          label="Client type"
          value={draft.isPublic ? "public" : "confidential"}
          disabled={mode !== "create"}
          onChange={(v) => set("isPublic", v === "public")}
          options={[
            { value: "confidential", label: "Confidential (server)" },
            { value: "public", label: "Public (SPA, mobile)" },
          ]}
        />
        <p className="mt-1.5 text-[12px] text-text-muted">
          {draft.isPublic
            ? "No secret: a browser or phone app cannot keep one. PKCE is mandatory."
            : "Has a secret, kept on the application's server."}
        </p>
      </Field>

      <Field
        label="Redirect URIs"
        htmlFor="c-redirect"
        hint="One per line, exact match (no wildcard). https, or http on localhost."
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
        label="Post-logout redirect URIs"
        htmlFor="c-logout"
        optional
        hint="Where users may land after signing out (one per line)."
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

      <Field label="Standard scopes" hint="openid is always on: it makes the request an OpenID Connect one.">
        <ChipSelect
          label="Standard scopes"
          options={STANDARD_SCOPES.map((s) => ({ id: s, name: s }))}
          value={draft.standardScopes}
          onChange={(v) => set("standardScopes", v.includes("openid") ? v : ["openid", ...v])}
        />
      </Field>

      {!draft.isPublic && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Token endpoint auth method" htmlFor="c-auth">
            <NativeSelect id="c-auth" value={draft.authMethod} onChange={(e) => set("authMethod", e.target.value)}>
              <option value="client_secret_basic">client_secret_basic</option>
              <option value="client_secret_post">client_secret_post</option>
            </NativeSelect>
          </Field>
          <div className="flex items-end pb-2.5">
            <CheckboxField
              id="c-pkce"
              label="Require PKCE"
              checked={draft.requirePkce}
              onCheckedChange={(v) => set("requirePkce", v === true)}
            />
          </div>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Access token (min)" htmlFor="c-at" hint="Empty: default" error={err("access_token_ttl")}>
          <Input
            id="c-at"
            inputMode="decimal"
            value={draft.accessTtlMinutes}
            onChange={(e) => set("accessTtlMinutes", e.target.value)}
          />
        </Field>
        <Field label="ID token (min)" htmlFor="c-it" hint="Empty: default" error={err("id_token_ttl")}>
          <Input
            id="c-it"
            inputMode="decimal"
            value={draft.idTtlMinutes}
            onChange={(e) => set("idTtlMinutes", e.target.value)}
          />
        </Field>
        <Field label="Refresh token (days)" htmlFor="c-rt" hint="Empty: default" error={err("refresh_token_ttl")}>
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
  return (
    <>
      <Field
        label="Entity ID"
        htmlFor="c-entity"
        hint="The service provider's identifier, from its metadata."
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
        label="ACS URL"
        htmlFor="c-acs"
        hint="Assertion Consumer Service: where the IdP posts the response."
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
      <Field label="NameID format" htmlFor="c-nameid" error={err("name_id_format")}>
        <NativeSelect id="c-nameid" value={draft.nameIdFormat} onChange={(e) => set("nameIdFormat", e.target.value)}>
          {NAME_ID_FORMATS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {mode === "create" && (
        <>
          <CheckboxField
            id="c-pairwise"
            label="Pairwise identifier"
            hint="This service provider gets its own persistent NameID per user: it cannot be matched with other providers."
            checked={draft.pairwise}
            onCheckedChange={(v) => set("pairwise", v === true)}
          />
          <Field
            label="Signing certificate (PEM)"
            htmlFor="c-cert"
            optional
            hint="The service provider's certificate, to verify its signed requests. More can be added later (rotation)."
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
  return (
    <div className="space-y-4 rounded-lg border border-border p-4">
      <Field label="SLO URL" htmlFor="c-slo" optional hint="Single Logout endpoint of the service provider.">
        <Input
          id="c-slo"
          className="font-mono text-[13px]"
          value={draft.sloUrl}
          onChange={(e) => set("sloUrl", e.target.value)}
        />
      </Field>
      <Field label="Default RelayState" htmlFor="c-relay" optional>
        <Input id="c-relay" value={draft.relayState} onChange={(e) => set("relayState", e.target.value)} />
      </Field>
      <div className="flex flex-wrap gap-6 text-[13px]">
        <span className="flex items-center gap-2">
          Assertion signed <TogglePill checked onLabel="Always" offLabel="No" label="Assertion signed" />
        </span>
        <span className="flex items-center gap-2">
          Response signed
          <TogglePill
            checked={draft.wantResponseSigned}
            onCheckedChange={(v) => set("wantResponseSigned", v)}
            onLabel="Yes"
            offLabel="No"
            label="Response signed"
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
  const [pem, setPem] = useState("");
  const [notBefore, setNotBefore] = useState("");
  const [notAfter, setNotAfter] = useState("");
  const [adding, setAdding] = useState(false);

  return (
    <div className="space-y-5 border-t border-border pt-5">
      {client.oidc?.client_type === "confidential" && (
        <Field
          label="Client secret"
          hint="Stored hashed: it cannot be shown again. Regenerate it if it was lost or leaked."
        >
          <div className="flex items-center gap-3">
            <code className="flex-1 rounded-sm border border-border bg-surface-alt px-3 py-2 font-mono text-[13px] text-text-muted">
              ••••••••••••••••••••
            </code>
            <ConfirmAction
              trigger={
                <>
                  <RefreshCw className="size-3.5" />
                  Regenerate
                </>
              }
              size="sm"
              variant="secondary"
              disabled={locked}
              title="Regenerate the client secret?"
              description="The current secret stops working at once: the application fails until it is configured with the new one."
              confirmLabel="Regenerate secret"
              action={() => rotateClientSecret(realm, client.id)}
              onDone={(d) => onSecret(d.secret)}
            />
          </div>
        </Field>
      )}

      {client.saml && (
        <div>
          <div className="mb-2 flex items-center justify-between">
            <p className="text-[13px] font-semibold text-text-secondary">Certificates</p>
            {!locked && !adding && (
              <Button size="xs" variant="secondary" onClick={() => setAdding(true)}>
                <Plus className="size-3.5" />
                Add (rotate)
              </Button>
            )}
          </div>
          <div className="space-y-2">
            {client.saml.certificates.length === 0 && (
              <p className="text-[13px] text-text-muted">
                No certificate: signed requests from this provider are refused.
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
                    Valid {formatDate(c.not_before ?? undefined)} → {formatDate(c.not_after ?? c.expires_at)}
                  </span>
                  {!locked && client.saml!.certificates.length > 1 && (
                    <ConfirmAction
                      trigger="Retire"
                      title="Retire this certificate?"
                      description="Requests signed with it are refused from now on."
                      confirmLabel="Retire"
                      action={() => removeCertificate(realm, client.id, c.fingerprint)}
                      success="Certificate retired"
                    />
                  )}
                </div>
              </div>
            ))}
          </div>
          {adding && (
            <div className="mt-3 space-y-3 rounded-lg border border-border p-3">
              <Field label="New certificate (PEM)" htmlFor="cert-pem">
                <Textarea
                  id="cert-pem"
                  className="font-mono text-[12px]"
                  rows={4}
                  value={pem}
                  onChange={(e) => setPem(e.target.value)}
                />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Valid from" htmlFor="cert-nb" optional>
                  <Input id="cert-nb" type="date" value={notBefore} onChange={(e) => setNotBefore(e.target.value)} />
                </Field>
                <Field label="Valid until" htmlFor="cert-na" optional>
                  <Input id="cert-na" type="date" value={notAfter} onChange={(e) => setNotAfter(e.target.value)} />
                </Field>
              </div>
              <p className="text-[12px] text-text-muted">
                Rotation: add the new certificate before the provider starts using it; retire the old one afterwards.
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
                      { success: "Certificate added" },
                    );
                    if (r.ok) {
                      setAdding(false);
                      setPem("");
                      setNotBefore("");
                      setNotAfter("");
                    }
                  }}
                >
                  Add certificate
                </Button>
                <Button size="xs" variant="secondary" onClick={() => setAdding(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {client.attribute_mappings && Object.keys(client.attribute_mappings).length > 0 && (
        <Field label="Attribute mappings" hint="Set by the configuration file or the CLI; read-only here.">
          <pre className="overflow-x-auto rounded-lg border border-border bg-surface-alt p-3 font-mono text-[12px]">
            {JSON.stringify(client.attribute_mappings, null, 2)}
          </pre>
        </Field>
      )}
    </div>
  );
}
