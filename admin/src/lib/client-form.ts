import { lines, secondsTo, toSeconds } from "@/lib/format";
import type { Client, ClientBody, Protocol } from "@/lib/types";

// The client drawer's form <-> the Admin API's JSON (POST/PATCH /clients).
// Pure functions: unit-tested in tests/client-form.test.ts.

export type ClientDraft = {
  protocol: Protocol;
  name: string;
  active: boolean;
  // OIDC
  clientId: string;
  isPublic: boolean;
  redirectUris: string;
  postLogoutUris: string;
  standardScopes: string[];
  authMethod: string;
  requirePkce: boolean;
  accessTtlMinutes: string;
  refreshTtlDays: string;
  idTtlMinutes: string;
  pairwise: boolean;
  // SAML
  entityId: string;
  acsUrl: string;
  sloUrl: string;
  nameIdFormat: string;
  wantResponseSigned: boolean;
  relayState: string;
  certificatePem: string;
  // both
  requireConsent: boolean;
  mfaPolicy: "inherit" | "required";
  mfaMethods: string[];
  scopes: { id: string; required: boolean }[];
  roleIds: string[];
  groupIds: string[];
};

export function emptyDraft(protocol: Protocol = "oidc"): ClientDraft {
  return {
    protocol,
    name: "",
    active: true,
    clientId: "",
    isPublic: false,
    redirectUris: "",
    postLogoutUris: "",
    standardScopes: ["openid", "profile", "email"],
    authMethod: "client_secret_basic",
    requirePkce: true,
    accessTtlMinutes: "",
    refreshTtlDays: "",
    idTtlMinutes: "",
    pairwise: false,
    entityId: "",
    acsUrl: "",
    sloUrl: "",
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    wantResponseSigned: true,
    relayState: "",
    certificatePem: "",
    requireConsent: false,
    mfaPolicy: "inherit",
    mfaMethods: [],
    scopes: [],
    roleIds: [],
    groupIds: [],
  };
}

export function draftFromClient(c: Client): ClientDraft {
  const d = emptyDraft(c.protocol);
  return {
    ...d,
    name: c.name,
    active: c.status === "active",
    clientId: c.client_id ?? "",
    isPublic: c.oidc?.client_type === "public",
    redirectUris: (c.oidc?.redirect_uris ?? []).join("\n"),
    postLogoutUris: (c.oidc?.post_logout_redirect_uris ?? []).join("\n"),
    standardScopes: c.oidc?.standard_scopes ?? d.standardScopes,
    authMethod: c.oidc?.token_endpoint_auth_method || d.authMethod,
    requirePkce: c.oidc?.require_pkce ?? true,
    accessTtlMinutes: secondsTo("minutes", c.oidc?.access_token_ttl ?? 0),
    refreshTtlDays: secondsTo("days", c.oidc?.refresh_token_ttl ?? 0),
    idTtlMinutes: secondsTo("minutes", c.oidc?.id_token_ttl ?? 0),
    pairwise: c.subject_type === "pairwise",
    entityId: c.saml?.entity_id ?? "",
    acsUrl: c.saml?.acs_url ?? "",
    sloUrl: c.saml?.slo_url ?? "",
    nameIdFormat: c.saml?.name_id_format || d.nameIdFormat,
    wantResponseSigned: c.saml?.want_response_signed ?? true,
    relayState: c.saml?.default_relay_state ?? "",
    requireConsent: c.require_consent,
    mfaPolicy: c.mfa_policy === "required" ? "required" : "inherit",
    mfaMethods: c.mfa_methods ?? [],
    scopes: c.client_scopes.map((s) => ({ id: s.id, required: s.required })),
    roleIds: c.allowed_roles.map((r) => r.id),
    groupIds: c.allowed_groups.map((g) => g.id),
  };
}

/**
 * The JSON body. "create": every field (POST). "update": no protocol,
 * client_id, public, pairwise or certificates (the API refuses them on PATCH;
 * certificates have their own endpoints).
 */
export function clientBody(d: ClientDraft, mode: "create" | "update"): ClientBody {
  const body: ClientBody = {
    name: d.name.trim(),
    active: d.active,
    require_consent: d.requireConsent,
    mfa_policy: d.mfaPolicy,
    mfa_methods: d.mfaMethods,
    client_scopes: d.scopes,
    allowed_role_ids: d.roleIds,
    allowed_group_ids: d.groupIds,
  };
  if (d.protocol === "oidc") {
    Object.assign(body, {
      redirect_uris: lines(d.redirectUris),
      post_logout_redirect_uris: lines(d.postLogoutUris),
      standard_scopes: d.standardScopes,
      token_endpoint_auth_method: d.isPublic ? "none" : d.authMethod,
      require_pkce: d.isPublic ? true : d.requirePkce,
      access_token_ttl: toSeconds("minutes", d.accessTtlMinutes),
      refresh_token_ttl: toSeconds("days", d.refreshTtlDays),
      id_token_ttl: toSeconds("minutes", d.idTtlMinutes),
    } satisfies ClientBody);
  } else {
    Object.assign(body, {
      entity_id: d.entityId.trim(),
      acs_url: d.acsUrl.trim(),
      slo_url: d.sloUrl.trim(),
      name_id_format: d.nameIdFormat,
      want_response_signed: d.wantResponseSigned,
      default_relay_state: d.relayState.trim(),
    } satisfies ClientBody);
  }
  if (mode === "create") {
    body.protocol = d.protocol;
    if (d.protocol === "oidc") {
      body.public = d.isPublic;
      if (d.clientId.trim()) body.client_id = d.clientId.trim();
    } else {
      // Pairwise: a different, persistent NameID per service provider.
      body.pairwise = d.pairwise;
      if (d.certificatePem.trim()) {
        body.certificates = [{ pem: d.certificatePem.trim(), not_before: null, not_after: null }];
      }
    }
  }
  return body;
}
