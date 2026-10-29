// JSON shapes of the Admin API (cmd/idp-admin, internal/adminapi). Kept by
// hand next to the Go structs they mirror: internal/core/service/admin*.go.
// Dates are RFC 3339 strings.

export type List<T> = { items: T[]; total: number; offset: number; limit: number };

export type ApiErrorBody = {
  error: string;
  message?: string;
  field?: string;
  allowed_methods?: string[];
  max_age_seconds?: number;
};

export type NameRef = { id: string; name: string };

export type Me = {
  user: { id: string; username: string; email: string; name: string };
  permissions: string[];
  step_up_fresh_until: string | null;
};

export type RealmStatus = "active" | "inactive";

export type Realm = {
  id: string;
  name: string;
  display_name: string;
  status: RealmStatus;
  system: boolean;
  created_at: string;
};

export type RealmDetail = Realm & { issuer: string; jwks_url: string; saml_metadata_url: string };

export type CreateRealmResult = { realm: Realm; warning?: string };

export type HealthLine = {
  name: string;
  status: "healthy" | "down" | "disabled";
  detail?: string;
  latency_ms: number;
};

export type AuditEntry = {
  id: string;
  timestamp: string;
  action: string;
  actor: { id: string; username: string; admin: boolean } | null;
  resource_type: string;
  resource_id: string;
  status: "success" | "failure";
  level: "debug" | "info" | "suspicious" | "warning" | "error" | "critical";
  ip_address: string;
  user_agent: string;
  details: Record<string, unknown>;
};

export type Dashboard = {
  active_sessions: number;
  active_clients: number;
  logins_24h: { success: number; failure: number; success_rate: number };
  mfa: { enrolled: number; total: number; percent: number };
  signing_keys: { kid: string; key_type: string; purpose: string; status: string; created_at: string }[];
  recent_activity: AuditEntry[];
  infrastructure: HealthLine[];
  realm: RealmDetail;
};

export type Protocol = "oidc" | "saml2";
export type ManagedBy = "ui" | "config";

export type ClientSummary = {
  id: string;
  name: string;
  protocol: Protocol;
  status: "active" | "inactive" | "suspended";
  managed_by: ManagedBy;
  client_id?: string;
  entity_id?: string;
  created_at: string;
};

export type ClientScopeChoice = { id: string; name: string; protocol: string; required: boolean };

export type Certificate = {
  fingerprint: string;
  subject: string;
  not_before: string | null;
  not_after: string | null;
  expires_at: string;
  status: "active" | "pending" | "expired";
};

export type Client = ClientSummary & {
  require_consent: boolean;
  subject_type: "public" | "pairwise";
  mfa_policy: "inherit" | "required";
  mfa_methods: string[];
  client_scopes: ClientScopeChoice[];
  allowed_roles: NameRef[];
  allowed_groups: NameRef[];
  oidc?: {
    client_type: "confidential" | "public";
    has_secret: boolean;
    redirect_uris: string[];
    post_logout_redirect_uris: string[];
    standard_scopes: string[];
    grant_types: string[];
    token_endpoint_auth_method: string;
    require_pkce: boolean;
    access_token_ttl: number;
    refresh_token_ttl: number;
    id_token_ttl: number;
  };
  saml?: {
    entity_id: string;
    acs_url: string;
    slo_url: string;
    name_id_format: string;
    want_assertion_signed: boolean;
    want_response_signed: boolean;
    default_relay_state: string;
    certificates: Certificate[];
  };
  attribute_mappings: Record<string, unknown> | null;
};

export type ClientCreated = { client: Client; secret?: string };

/** Body of POST/PATCH /clients (absent fields: unchanged or default). */
export type ClientBody = {
  protocol?: Protocol;
  name?: string;
  active?: boolean;
  client_id?: string;
  public?: boolean;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  standard_scopes?: string[];
  token_endpoint_auth_method?: string;
  require_pkce?: boolean;
  access_token_ttl?: number;
  refresh_token_ttl?: number;
  id_token_ttl?: number;
  entity_id?: string;
  acs_url?: string;
  slo_url?: string;
  name_id_format?: string;
  want_response_signed?: boolean;
  default_relay_state?: string;
  pairwise?: boolean;
  certificates?: { pem: string; not_before: string | null; not_after: string | null }[];
  client_scopes?: { id: string; required: boolean }[];
  allowed_role_ids?: string[];
  allowed_group_ids?: string[];
  require_consent?: boolean;
  mfa_policy?: string;
  mfa_methods?: string[];
};

export type ClaimMapper = { source_attribute: string; claim_name: string; token_location: string[] };

export type ClientScope = {
  id: string;
  name: string;
  description: string;
  protocol: "oidc" | "saml2" | "both";
  is_default: boolean;
  claim_mappers: ClaimMapper[];
  clients: number;
  created_at: string;
};

export type SessionRow = {
  id: string;
  user: NameRef;
  user_email: string;
  ip_address: string;
  user_agent: string;
  device: string;
  auth_method: string;
  mfa_verified: boolean;
  mfa_method: string;
  /** "Keep me signed in" was ticked: long-lived session, persistent cookie. */
  remember_me: boolean;
  /** The second factor was skipped: the device is trusted ("Don't ask again on this device"). */
  trusted_device: boolean;
  clients: NameRef[];
  created_at: string;
  last_activity_at: string;
  expires_at: string;
};

export type UserStatus = "active" | "inactive" | "suspended";

export type UserSummary = {
  id: string;
  username: string;
  email: string;
  name: string;
  status: UserStatus;
  has_password: boolean;
  mfa_enrolled: boolean;
  locked: boolean;
  last_login_at: string | null;
  created_at: string;
  groups: NameRef[];
  roles: NameRef[];
};

export type Factor = { id: string; type: string; name: string; created_at: string; last_used_at: string | null };

/** A device where the user ticked "Don't ask again on this device", still trusted. */
export type TrustedDevice = {
  id: string;
  /** Of the last sign-in that used it (first: where the box was ticked). */
  ip_address: string;
  user_agent: string;
  /** "Firefox on Windows". */
  device: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
};
export type EffectiveGrant = { id: string; name: string; sources: string[] };

export type UserDetail = UserSummary & {
  profile: Record<string, unknown>;
  failed_logins: number;
  locked_until: string | null;
  factors: Factor[];
  backup_codes_left: number;
  effective: { permissions: EffectiveGrant[]; client_scopes: EffectiveGrant[] };
  trusted_devices: TrustedDevice[];
};

export type InviteResult = { user: UserDetail; emailed: boolean; activation_url?: string; expires_at: string };

export type Access = {
  id: string;
  kind: "role" | "group";
  name: string;
  description: string;
  status: string;
  managed_by: ManagedBy;
  members: number;
  permission_ids: string[];
  client_scope_ids: string[];
  created_at: string;
  notice?: string;
};

export type Permission = {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
  system: boolean;
};

export type SigningKey = {
  kid: string;
  key_type: "RSA" | "EC" | "AES";
  algorithm: string;
  /** envelope_encryption: an AES key encrypting MFA secrets at rest (not a signature key). */
  purpose: "jwt_signing" | "saml_signing" | "saml_encryption" | "envelope_encryption";
  status: "active" | "pending" | "rotating" | "retired";
  kms_backend: string;
  created_at: string;
  retire_after?: string;
  retired_at?: string;
};

export type SigningKeys = { keys: SigningKey[]; jwks_url: string; saml_metadata_url: string };

export type RotateResult = {
  new_key: SigningKey;
  rotating: SigningKey[];
  retired: SigningKey[];
  grace_hours: number;
  warning?: string;
};

export type RolePolicy = {
  role: NameRef;
  configured: boolean;
  required: boolean;
  allowed_methods: string[];
  enrollment_grace_days: number;
  step_up_for_sensitive_actions: boolean;
  managed_by: ManagedBy;
};

export type MfaPolicies = {
  required_globally: boolean;
  step_up_max_age_minutes: number;
  /** "Don't ask again on this device" is offered after a second factor. */
  trusted_devices_enabled: boolean;
  trusted_device_days: number;
  roles: RolePolicy[];
  clients: { client: NameRef; policy: string; methods: string[] }[];
  known_methods: string[];
};

export type Settings = {
  managed_by: ManagedBy;
  min_password_length: number;
  password_expiry_days: number;
  password_reset_ttl_minutes: number;
  session_idle_minutes: number;
  session_max_hours: number;
  remember_me_enabled: boolean;
  remember_me_idle_days: number;
  remember_me_max_days: number;
  lockout_threshold: number;
  lockout_duration_minutes: number;
  ip_allowlist: string[];
  mfa_required_globally: boolean;
  mfa_step_up_max_age_minutes: number;
  key_rotation_grace_hours: number;
  notification_email_enabled: boolean;
  suspicious_login_email_enabled: boolean;
  updated_at: string;
  updated_by: string;
  email_enabled: boolean;
};

export type TimeoutTargetType = "user" | "group" | "client";
export type TimeoutStatus = "scheduled" | "active" | "ended" | "lifted";

export type Timeout = {
  id: string;
  target_type: TimeoutTargetType;
  target: NameRef;
  starts_at: string;
  ends_at: string | null; // null: no end, until lifted
  reason: string;
  created_by: string; // administrator's username, or "cli:<os user>"
  created_at: string;
  status: TimeoutStatus;
  active: boolean;
  lifted_at: string | null;
  lifted_by: string;
  enforced_at: string | null; // when the targets were signed out
  // Only in the answer to a create that started at once.
  sign_out?: { users: number; sessions: number; tokens: number };
  sign_out_pending?: boolean;
};
