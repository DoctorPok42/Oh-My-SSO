package domain

import "time"

// KnownAccount is an account shown in "Pick an account" on one device (the
// user ticked "Keep me signed in" there). It stays until "Forget".
type KnownAccount struct {
	ID         string
	RealmID    string
	UserID     string
	DeviceHash string // SHA-256 of the sso_device cookie
	CreatedAt  time.Time
	LastUsedAt time.Time
	// LastMethod, LastSecondFactor: how the user likes to sign in on this
	// device (Step 18e); "" when they never had to choose.
	LastMethod       string // "password" or "passkey"
	LastSecondFactor string // "passkey" or "totp"
}

// LogoutVia tells how a user signed out, in the audit log.
type LogoutVia string

const (
	LogoutViaAPI           LogoutVia = "auth_api"       // POST /auth/logout
	LogoutViaOIDC          LogoutVia = "oidc"           // RP-initiated logout (end_session_endpoint)
	LogoutViaSAML          LogoutVia = "saml_slo"       // SAML Single Logout
	LogoutViaAccountSwitch LogoutVia = "account_switch" // another account signed in in this browser
	LogoutViaForget        LogoutVia = "forget"         // "Sign out and forget" on the sign-in page
)
