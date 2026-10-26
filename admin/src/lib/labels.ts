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
  hwk: "Security key",
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

/** "admin.client.update" -> "Client updated" style labels for the most common actions. */
export function actionLabel(action: string): string {
  return action
    .replace(/^admin\./, "")
    .replaceAll("_", " ")
    .replaceAll(".", " · ");
}

export function isNotification(action: string): boolean {
  return action.startsWith("notification") || action.includes("email_sent") || action.includes("notification_sent");
}

export const KEY_PURPOSE_LABELS: Record<string, string> = {
  jwt_signing: "OIDC tokens (JWT)",
  saml_signing: "SAML signing",
  saml_encryption: "SAML encryption",
  envelope_encryption: "Data encryption (MFA secrets)",
};
