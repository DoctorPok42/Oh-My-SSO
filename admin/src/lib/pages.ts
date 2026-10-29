// Title, subtitle and table columns of each console page, in one place: the
// page shows them, and so does its skeleton (loading.tsx) while the data is
// on its way, so the admin sees at once where they are.

export const PAGES = {
  dashboard: { title: "Dashboard", description: "Identity provider overview" },
  clients: { title: "Clients", description: "Applications federated via OpenID Connect or SAML 2.0" },
  clientScopes: {
    title: "Client Scopes",
    description: "Reusable claim sets granted to clients: which user attributes go into which token",
  },
  sessions: { title: "Sessions", description: "Active sessions across all users and applications" },
  audit: { title: "Audit Log", description: "Every sensitive action in this realm, in order" },
  users: { title: "Users & Roles", description: "Identities and access levels of this realm" },
  signingKeys: {
    title: "Signing Keys",
    description: "Keys that sign this realm's tokens and SAML assertions. Private keys stay in the key manager.",
  },
  mfa: { title: "MFA Policies", description: "Who must use a second factor, which one, and when to ask again" },
  timeouts: {
    title: "Timeouts",
    description: "Suspend a user, a group or an application for a while: no sign-in, no token, until it ends",
  },
  settings: { title: "Settings", description: "Security policy of this realm and infrastructure status" },
  realms: { title: "Realms", description: "Separate identity spaces: users, applications, keys and policies" },
} as const;

/** Column headers ("" = an actions column without a visible header). */
export const COLUMNS = {
  clients: ["Name", "Protocol", "Client / Entity ID", "Status", "Created", ""],
  clientScopes: ["Name", "Protocol", "Type", "Claims", "Used by", ""],
  sessions: ["User", "IP address", "Device", "Applications", "Auth method", "MFA", "Last active", "Expires", ""],
  audit: ["Timestamp", "Actor", "Action", "Target", "IP", "Status"],
  users: ["Name", "Email", "Groups", "MFA", "Status", "Last login", ""],
  access: ["Name", "Members", "Permissions", "Client scopes", "Status", ""],
  permissions: ["Permission", "Description", "Type", ""],
  signingKeys: ["Key ID", "Algorithm", "Used for", "Status", "Created", "Unpublished", "Key manager"],
  timeouts: ["Target", "Start", "End", "Reason", "Created by", "Status", ""],
  realms: ["Display name", "Name", "Status", "Created", ""],
  mfaRoles: ["Role", "Policy", "MFA required", "Step-up for sensitive actions", "Grace period", "Allowed methods", ""],
  mfaClients: ["Client", "Policy", "Accepted methods"],
} as const;
