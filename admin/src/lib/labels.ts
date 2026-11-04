import { english, m, type Msg, type Translator } from "@/i18n";

// Human labels for the API's codes, to translate where they are shown (tm).

export const MFA_METHOD_LABELS: Record<string, Msg> = {
  totp: m("labels.mfa.totp", "Authenticator app (TOTP)"),
  webauthn: m("labels.mfa.webauthn", "Security key (WebAuthn)"),
  passkey: m("labels.mfa.passkey", "Passkey"),
  backup_codes: m("labels.mfa.backup_codes", "Backup codes"),
  biometric: m("labels.mfa.biometric", "Biometric"),
};

/** Second factors a client or a role can require (domain.MfaMethodType). */
export const MFA_METHODS = ["totp", "webauthn", "passkey", "backup_codes"];

/** RFC 8176 "amr" values. */
export const AUTH_METHOD_LABELS: Record<string, Msg> = {
  pwd: m("labels.amr.pwd", "Password"),
  otp: m("labels.amr.otp", "Password + code"),
  mfa: m("labels.amr.mfa", "Multi-factor"),
  hwk: m("labels.amr.hwk", "Passkey or security key"),
  swk: m("labels.amr.swk", "Passkey"),
  sms: m("labels.amr.sms", "SMS"),
};

export const PROTOCOL_LABELS: Record<string, string> = { oidc: "OIDC", saml2: "SAML 2.0", both: "OIDC + SAML" };

export const NAME_ID_FORMATS = [
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: m("labels.nameid.persistent", "Persistent") },
  { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: m("labels.nameid.transient", "Transient") },
  { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: m("labels.nameid.email", "Email address") },
  {
    value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    label: m("labels.nameid.unspecified", "Unspecified"),
  },
];

export const STANDARD_SCOPES = ["openid", "profile", "email", "offline_access"];

export const TOKEN_LOCATIONS = [
  { value: "id_token", label: m("labels.location.id_token", "ID token") },
  { value: "access_token", label: m("labels.location.access_token", "Access token") },
  { value: "userinfo", label: m("labels.location.userinfo", "UserInfo") },
  { value: "saml_attribute", label: m("labels.location.saml_attribute", "SAML attribute") },
];

/**
 * A readable label for an action code, in the console's language: its
 * translation (audit.action.<code>, the catalogue of internal/core/audit),
 * else the catalogue's label, else "client.secret_rotated" -> "Client ·
 * secret rotated".
 */
export function actionLabel(action: string, catalog?: ReadonlyMap<string, string>, tr: Translator = english): string {
  const known = catalog?.get(action);
  const text = action.replaceAll("_", " ").replaceAll(".", " · ");
  return tr.t(`audit.action.${action}`, known || text.charAt(0).toUpperCase() + text.slice(1));
}

/** A category of the action catalogue ("Authentication"), in the console's language. */
export function categoryLabel(category: string, tr: Translator = english): string {
  return tr.t(`audit.category.${category.toLowerCase().replaceAll(" ", "_")}`, category);
}

export function isNotification(action: string): boolean {
  return action.startsWith("notification.");
}

/** Who did it, as the audit log's actor badge says it. */
export const ACTOR_TYPE_LABELS: Record<string, Msg> = {
  user: m("labels.actor.user", "User"),
  admin: m("labels.actor.admin", "Admin"),
  cli: m("labels.actor.cli", "CLI"),
  system: m("labels.actor.system", "System"),
  anonymous: m("labels.actor.anonymous", "Anonymous"),
};

/** The actor's name for a list: the username, else the kind of actor. */
export function actorName(
  entry: { actor_type?: string; actor: { username: string; id: string } | null },
  tr: Translator = english,
): string {
  if (entry.actor) return entry.actor.username || entry.actor.id;
  const label = ACTOR_TYPE_LABELS[entry.actor_type ?? "system"];
  return label ? tr.tm(label).toLowerCase() : tr.t("labels.actor.system", "System").toLowerCase();
}

export const KEY_PURPOSE_LABELS: Record<string, Msg> = {
  jwt_signing: m("labels.key.jwt_signing", "OIDC tokens (JWT)"),
  saml_signing: m("labels.key.saml_signing", "SAML signing"),
  saml_encryption: m("labels.key.saml_encryption", "SAML encryption"),
  envelope_encryption: m("labels.key.envelope_encryption", "Data encryption (MFA secrets)"),
};
