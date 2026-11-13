package audit

// Every action the audit log can hold, named "<domain>.<what happened>"
// (past tense: an entry records a fact). Who did it is not part of the name:
// the entry's actor type tells a user, an administrator, the CLI or the
// server itself apart (session.revoked by the user from their account
// console, or by an admin, is the same action).
//
// Writers use these constants, never a literal: the admin console's filter
// lists Catalog, and a name that is not in it could not be searched for.
const (
	// Sign-in, sign-out, authorization.
	AuthLogin                   = "auth.login"            // a sign-in succeeded (a session was created)
	AuthLoginNewDevice          = "auth.login_new_device" // ... from a device never seen for this user
	AuthLoginSuspicious         = "auth.login_suspicious" // ... with signs of risk (new country, impossible travel...)
	AuthLoginFailed             = "auth.login_failed"     // a wrong password, an unknown account, a locked one...
	AuthMFAFailed               = "auth.mfa_failed"       // a wrong second factor
	AuthLogout                  = "auth.logout"
	AuthTrustedDeviceChallenged = "auth.trusted_device_challenged" // a trusted device had to give the second factor anyway
	AuthAccessDenied            = "auth.access_denied"             // signed in, but no right to the application
	TokenReuseDetected          = "token.reuse_detected"           // a refresh token was replayed: its family is revoked

	// Users.
	UserInvited                = "user.invited"
	UserActivationLinkSent     = "user.activation_link_sent"
	UserImportStarted          = "user.import_started"  // a CSV file of users, running in the background
	UserImportFinished         = "user.import_finished" // ... its totals; one user.invited per account created
	BulkCompleted              = "bulk.completed"       // a bulk action of the console: its only entry, listing each item and the changes made
	BulkInterrupted            = "bulk.interrupted"     // the same, for a bulk action stopped half-way (server stopped): also lists the items not processed
	UserUpdated                = "user.updated"         // by an administrator
	UserProfileUpdated         = "user.profile_updated"
	UserDeleted                = "user.deleted"
	UserGroupsChanged          = "user.groups_changed"
	UserRolesChanged           = "user.roles_changed"
	UserLocked                 = "user.locked"
	UserUnlocked               = "user.unlocked"
	UserPasswordChanged        = "user.password_changed"
	UserPasswordResetRequested = "user.password_reset_requested"
	UserPasswordReset          = "user.password_reset"
	UserPasswordResetForced    = "user.password_reset_forced" // by an administrator

	// Second factors.
	MFAMethodEnrolled         = "mfa.method_enrolled"
	MFAMethodRemoved          = "mfa.method_removed"
	MFABackupCodesRegenerated = "mfa.backup_codes_regenerated"
	MFAPasskeyCloneDetected   = "mfa.passkey_clone_detected"
	MFAReset                  = "mfa.reset"
	MFAPolicyChanged          = "mfa.policy_changed"

	// Trusted devices ("don't ask again on this device").
	TrustedDeviceAdded      = "trusted_device.added"
	TrustedDeviceRevoked    = "trusted_device.revoked"
	TrustedDeviceRevokedAll = "trusted_device.revoked_all"

	// Sessions.
	SessionRevoked    = "session.revoked"
	SessionRevokedAll = "session.revoked_all"

	// Consents.
	ConsentGranted          = "consent.granted"
	ConsentDenied           = "consent.denied"
	ConsentRevoked          = "consent.revoked"
	ConsentAppAccessRevoked = "consent.app_access_revoked"
	ConsentPolicyChanged    = "consent.policy_changed"

	// Account picker.
	KnownAccountForgotten = "known_account.forgotten"

	// Applications.
	ClientCreated            = "client.created"
	ClientUpdated            = "client.updated"
	ClientDeleted            = "client.deleted"
	ClientSecretRotated      = "client.secret_rotated"
	ClientCertificateAdded   = "client.certificate_added"
	ClientCertificateRemoved = "client.certificate_removed"
	ClientScopeCreated       = "client_scope.created"
	ClientScopeUpdated       = "client_scope.updated"
	ClientScopeDeleted       = "client_scope.deleted"

	// Access control.
	RoleCreated       = "role.created"
	RoleUpdated       = "role.updated"
	RoleDeleted       = "role.deleted"
	GroupCreated      = "group.created"
	GroupUpdated      = "group.updated"
	GroupDeleted      = "group.deleted"
	PermissionCreated = "permission.created"
	PermissionDeleted = "permission.deleted"

	// Timeouts.
	TimeoutCreated  = "timeout.created"
	TimeoutUpdated  = "timeout.updated"
	TimeoutLifted   = "timeout.lifted"
	TimeoutEnforced = "timeout.enforced"

	// Signing keys.
	SigningKeyCreated     = "signing_key.created"
	SigningKeyRotated     = "signing_key.rotated" // superseded, in its grace period
	SigningKeyActivated   = "signing_key.activated"
	SigningKeyRetired     = "signing_key.retired"
	SigningKeyCompromised = "signing_key.compromised"

	// Realms and settings.
	RealmCreated    = "realm.created"
	RealmUpdated    = "realm.updated"
	SettingsUpdated = "settings.updated"

	// Instance setup and recovery (CLI).
	InstanceBootstrapped  = "instance.bootstrapped"
	RecoveryAdmin         = "recovery.admin"
	RecoveryClientSecret  = "recovery.client_secret"
	RecoveryTimeoutLifted = "recovery.timeout_lifted"

	// E-mails.
	NotificationSent = "notification.sent"

	// The audit log itself.
	AuditLogExported = "audit_log.exported"
	AuditLogPurged   = "audit_log.purged" // entries older than the realm's retention deleted (by the server, at each purge pass)
)

// ActionInfo describes one action for the admin console (filter, labels).
type ActionInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Label    string `json:"label"`
}

// Catalog lists every action, grouped by category, in display order.
var Catalog = []ActionInfo{
	{AuthLogin, "Authentication", "Signed in"},
	{AuthLoginNewDevice, "Authentication", "Signed in from a new device"},
	{AuthLoginSuspicious, "Authentication", "Suspicious sign-in"},
	{AuthLoginFailed, "Authentication", "Sign-in failed"},
	{AuthMFAFailed, "Authentication", "Second factor failed"},
	{AuthLogout, "Authentication", "Signed out"},
	{AuthTrustedDeviceChallenged, "Authentication", "Trusted device asked for the second factor"},
	{AuthAccessDenied, "Authentication", "Access to an application denied"},
	{TokenReuseDetected, "Authentication", "Refresh token reuse detected"},

	{UserInvited, "Users", "User invited"},
	{UserActivationLinkSent, "Users", "Activation link sent"},
	{UserImportStarted, "Users", "User import started"},
	{UserImportFinished, "Users", "User import finished"},
	{BulkCompleted, "Users", "Bulk action"},
	{BulkInterrupted, "Users", "Bulk action interrupted"},
	{UserUpdated, "Users", "User updated"},
	{UserProfileUpdated, "Users", "Profile updated"},
	{UserDeleted, "Users", "User deleted"},
	{UserGroupsChanged, "Users", "Groups changed"},
	{UserRolesChanged, "Users", "Roles changed"},
	{UserLocked, "Users", "Account locked"},
	{UserUnlocked, "Users", "Account unlocked"},
	{UserPasswordChanged, "Users", "Password changed"},
	{UserPasswordResetRequested, "Users", "Password reset requested"},
	{UserPasswordReset, "Users", "Password reset"},
	{UserPasswordResetForced, "Users", "Password reset forced by an administrator"},

	{MFAMethodEnrolled, "Second factors", "Factor enrolled"},
	{MFAMethodRemoved, "Second factors", "Factor removed"},
	{MFABackupCodesRegenerated, "Second factors", "Backup codes regenerated"},
	{MFAPasskeyCloneDetected, "Second factors", "Possible passkey clone"},
	{MFAReset, "Second factors", "Second factors reset"},
	{MFAPolicyChanged, "Second factors", "MFA policy changed"},
	{TrustedDeviceAdded, "Second factors", "Device trusted"},
	{TrustedDeviceRevoked, "Second factors", "Trusted device revoked"},
	{TrustedDeviceRevokedAll, "Second factors", "Every trusted device revoked"},

	{SessionRevoked, "Sessions", "Session revoked"},
	{SessionRevokedAll, "Sessions", "Every session revoked"},
	{KnownAccountForgotten, "Sessions", "Account forgotten on a device"},

	{ConsentGranted, "Consents", "Consent granted"},
	{ConsentDenied, "Consents", "Consent denied"},
	{ConsentRevoked, "Consents", "Consent revoked"},
	{ConsentAppAccessRevoked, "Consents", "Application access revoked"},
	{ConsentPolicyChanged, "Consents", "Consent requirement changed"},

	{ClientCreated, "Applications", "Application created"},
	{ClientUpdated, "Applications", "Application updated"},
	{ClientDeleted, "Applications", "Application deleted"},
	{ClientSecretRotated, "Applications", "Client secret rotated"},
	{ClientCertificateAdded, "Applications", "Certificate added"},
	{ClientCertificateRemoved, "Applications", "Certificate removed"},
	{ClientScopeCreated, "Applications", "Client scope created"},
	{ClientScopeUpdated, "Applications", "Client scope updated"},
	{ClientScopeDeleted, "Applications", "Client scope deleted"},

	{RoleCreated, "Access control", "Role created"},
	{RoleUpdated, "Access control", "Role updated"},
	{RoleDeleted, "Access control", "Role deleted"},
	{GroupCreated, "Access control", "Group created"},
	{GroupUpdated, "Access control", "Group updated"},
	{GroupDeleted, "Access control", "Group deleted"},
	{PermissionCreated, "Access control", "Permission created"},
	{PermissionDeleted, "Access control", "Permission deleted"},

	{TimeoutCreated, "Timeouts", "Timeout created"},
	{TimeoutUpdated, "Timeouts", "Timeout updated"},
	{TimeoutLifted, "Timeouts", "Timeout lifted"},
	{TimeoutEnforced, "Timeouts", "Timeout enforced (signed out)"},

	{SigningKeyCreated, "Signing keys", "Key created"},
	{SigningKeyRotated, "Signing keys", "Key rotated"},
	{SigningKeyActivated, "Signing keys", "Key activated"},
	{SigningKeyRetired, "Signing keys", "Key retired"},
	{SigningKeyCompromised, "Signing keys", "Key marked compromised"},

	{RealmCreated, "Realm", "Realm created"},
	{RealmUpdated, "Realm", "Realm updated"},
	{SettingsUpdated, "Realm", "Settings updated"},
	{InstanceBootstrapped, "Realm", "Instance bootstrapped"},
	{RecoveryAdmin, "Realm", "Administrator access recovered"},
	{RecoveryClientSecret, "Realm", "Console client secret recovered"},
	{RecoveryTimeoutLifted, "Realm", "Timeout lifted (recovery)"},

	{NotificationSent, "E-mails", "E-mail sent"},

	{AuditLogExported, "Audit log", "Audit log exported"},
	{AuditLogPurged, "Audit log", "Old audit log entries deleted"},
}

// Known reports whether name is in Catalog.
func Known(name string) bool {
	for _, a := range Catalog {
		if a.Name == name {
			return true
		}
	}
	return false
}
