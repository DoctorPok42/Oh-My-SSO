import { m, type Msg } from "@/i18n";

// Title, subtitle and table columns of each console page, in one place: the
// page shows them, and so does its skeleton (loading.tsx) while the data is
// on its way, so the admin sees at once where they are. Texts to translate
// where they are shown (tm, src/i18n).

export const PAGES = {
  dashboard: {
    title: m("pages.dashboard.title", "Dashboard"),
    description: m("pages.dashboard.description", "Identity provider overview"),
  },
  clients: {
    title: m("pages.clients.title", "Clients"),
    description: m("pages.clients.description", "Applications federated via OpenID Connect or SAML 2.0"),
  },
  clientScopes: {
    title: m("pages.client_scopes.title", "Client Scopes"),
    description: m(
      "pages.client_scopes.description",
      "Reusable claim sets granted to clients: which user attributes go into which token",
    ),
  },
  sessions: {
    title: m("pages.sessions.title", "Sessions"),
    description: m("pages.sessions.description", "Active sessions across all users and applications"),
  },
  audit: {
    title: m("pages.audit.title", "Audit Log"),
    description: m("pages.audit.description", "Every sensitive action in this realm, in order"),
  },
  users: {
    title: m("pages.users.title", "Users"),
    description: m("pages.users.description", "People who can sign in to this realm"),
  },
  roles: {
    title: m("pages.roles.title", "Roles"),
    description: m("pages.roles.description", "Sets of permissions given to users"),
  },
  groups: {
    title: m("pages.groups.title", "Groups"),
    description: m("pages.groups.description", "Users who share the same access and client scopes"),
  },
  permissions: {
    title: m("pages.permissions.title", "Permissions"),
    description: m("pages.permissions.description", "What applications check, as resource:action"),
  },
  signingKeys: {
    title: m("pages.signing_keys.title", "Signing Keys"),
    description: m(
      "pages.signing_keys.description",
      "Keys that sign this realm's tokens and SAML assertions. Private keys stay in the key manager.",
    ),
  },
  mfa: {
    title: m("pages.mfa.title", "MFA Policies"),
    description: m("pages.mfa.description", "Who must use a second factor, which one, and when to ask again"),
  },
  timeouts: {
    title: m("pages.timeouts.title", "Timeouts"),
    description: m(
      "pages.timeouts.description",
      "Suspend a user, a group or an application for a while: no sign-in, no token, until it ends",
    ),
  },
  settingsGeneral: {
    title: m("pages.settings_general.title", "General"),
    description: m(
      "pages.settings_general.description",
      "This realm, its default language and the infrastructure status",
    ),
  },
  settingsSecurity: {
    title: m("pages.settings_security.title", "Security"),
    description: m(
      "pages.settings_security.description",
      "Password rules, brute-force protection and signing key rotation",
    ),
  },
  settingsSessions: {
    title: m("pages.settings_sessions.title", "Sessions"),
    description: m("pages.settings_sessions.description", "How long a sign-in lasts at the identity provider"),
  },
  settingsEmail: {
    title: m("pages.settings_email.title", "Email"),
    description: m(
      "pages.settings_email.description",
      "Security e-mails sent to users and how they appear in the inbox",
    ),
  },
  settingsAudit: {
    title: m("pages.settings_audit.title", "Audit"),
    description: m("pages.settings_audit.description", "How long the audit log of this realm is kept"),
  },
  realms: {
    title: m("pages.realms.title", "Realms"),
    description: m("pages.realms.description", "Separate identity spaces: users, applications, keys and policies"),
  },
} as const;

const col = {
  name: m("columns.name", "Name"),
  protocol: m("columns.protocol", "Protocol"),
  status: m("columns.status", "Status"),
  created: m("columns.created", "Created"),
  permissions: m("columns.permissions", "Permissions"),
  clientScopes: m("columns.client_scopes", "Client scopes"),
};

/** Column headers ("" = an actions column without a visible header). */
export const COLUMNS = {
  clients: [col.name, col.protocol, m("columns.client_id", "Client / Entity ID"), col.status, col.created, ""],
  clientScopes: [
    col.name,
    col.protocol,
    m("columns.type", "Type"),
    m("columns.claims", "Claims"),
    m("columns.used_by", "Used by"),
    "",
  ],
  sessions: [
    m("columns.user", "User"),
    m("columns.ip_address", "IP address"),
    m("columns.device", "Device"),
    m("columns.applications", "Applications"),
    m("columns.auth_method", "Auth method"),
    m("columns.mfa", "MFA"),
    m("columns.last_active", "Last active"),
    m("columns.expires", "Expires"),
    "",
  ],
  audit: [
    m("columns.timestamp", "Timestamp"),
    m("columns.actor", "Actor"),
    m("columns.action", "Action"),
    m("columns.target", "Target"),
    m("columns.ip", "IP"),
    col.status,
  ],
  users: [
    col.name,
    m("columns.email", "Email"),
    m("columns.groups", "Groups"),
    m("columns.mfa", "MFA"),
    col.status,
    m("columns.last_login", "Last login"),
    "",
  ],
  access: [col.name, m("columns.members", "Members"), col.permissions, col.clientScopes, col.status, ""],
  permissions: [
    m("columns.permission", "Permission"),
    m("columns.description", "Description"),
    m("columns.type", "Type"),
    "",
  ],
  signingKeys: [
    m("columns.key_id", "Key ID"),
    m("columns.algorithm", "Algorithm"),
    m("columns.used_for", "Used for"),
    col.status,
    col.created,
    m("columns.unpublished", "Unpublished"),
    m("columns.key_manager", "Key manager"),
  ],
  timeouts: [
    m("columns.target", "Target"),
    m("columns.start", "Start"),
    m("columns.end", "End"),
    m("columns.reason", "Reason"),
    m("columns.created_by", "Created by"),
    col.status,
    "",
  ],
  realms: [m("columns.display_name", "Display name"), col.name, col.status, col.created, ""],
  mfaRoles: [
    m("columns.role", "Role"),
    m("columns.policy", "Policy"),
    m("columns.mfa_required", "MFA required"),
    m("columns.step_up", "Step-up for sensitive actions"),
    m("columns.grace_period", "Grace period"),
    m("columns.allowed_methods", "Allowed methods"),
    "",
  ],
  mfaClients: [
    m("columns.client", "Client"),
    m("columns.policy", "Policy"),
    m("columns.accepted_methods", "Accepted methods"),
  ],
} satisfies Record<string, readonly (Msg | "")[]>;
