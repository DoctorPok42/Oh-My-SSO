// Human labels for the API's codes.

export const MFA_METHOD_LABELS: Record<string, string> = {
  totp: "Authenticator app (TOTP)",
  webauthn: "Security key (WebAuthn)",
  passkey: "Passkey",
  backup_codes: "Backup codes",
  biometric: "Biometric",
};

/** Second factors a client or a role can require (domain.MfaMethodType). */
export const MFA_METHODS = ["totp", "webauthn", "passkey", "backup_codes"];

/** RFC 8176 "amr" values. */
export const AUTH_METHOD_LABELS: Record<string, string> = {
  pwd: "Password",
  otp: "Password + code",
  mfa: "Multi-factor",
  hwk: "Passkey or security key",
  swk: "Passkey",
  sms: "SMS",
};

export const PROTOCOL_LABELS: Record<string, string> = { oidc: "OIDC", saml2: "SAML 2.0", both: "OIDC + SAML" };

export const NAME_ID_FORMATS = [
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: "Persistent" },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: "Transient" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: "Email address" },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", label: "Unspecified" },
];

export const STANDARD_SCOPES = ["openid", "profile", "email", "offline_access"];

export const TOKEN_LOCATIONS = [
  { value: "id_token", label: "ID token" },
  { value: "access_token", label: "Access token" },
  { value: "userinfo", label: "UserInfo" },
  { value: "saml_attribute", label: "SAML attribute" },
];

/**
 * A readable label for an action code: the catalogue's label when given,
 * else "client.secret_rotated" -> "Client · secret rotated".
 */
export function actionLabel(action: string, catalog?: ReadonlyMap<string, string>): string {
  const known = catalog?.get(action);
  if (known) return known;
  const text = action.replaceAll("_", " ").replaceAll(".", " · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function isNotification(action: string): boolean {
  return action.startsWith("notification.");
}

/** Who did it, as the audit log's actor badge says it. */
export const ACTOR_TYPE_LABELS: Record<string, string> = {
  user: "User",
  admin: "Admin",
  cli: "CLI",
  system: "System",
  anonymous: "Anonymous",
};

/** The actor's name for a list: the username, else the kind of actor. */
export function actorName(entry: { actor_type?: string; actor: { username: string; id: string } | null }): string {
  if (entry.actor) return entry.actor.username || entry.actor.id;
  return ACTOR_TYPE_LABELS[entry.actor_type ?? "system"]?.toLowerCase() ?? "system";
}

export const KEY_PURPOSE_LABELS: Record<string, string> = {
  jwt_signing: "OIDC tokens (JWT)",
  saml_signing: "SAML signing",
  saml_encryption: "SAML encryption",
  envelope_encryption: "Data encryption (MFA secrets)",
};
