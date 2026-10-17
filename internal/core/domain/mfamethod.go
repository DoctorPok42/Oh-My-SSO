package domain

import "time"

type MfaMethodType string

const (
	MfaMethodTOTP        MfaMethodType = "totp"
	MfaMethodWebAuthn    MfaMethodType = "webauthn"
	MfaMethodPasskey     MfaMethodType = "passkey"
	MfaMethodBackupCodes MfaMethodType = "backup_codes"
	MfaMethodBiometric   MfaMethodType = "biometric"
)

type MfaMethodStatus string

const (
	// MfaMethodPending: enrollment started, not confirmed yet. Never usable.
	MfaMethodPending  MfaMethodStatus = "pending"
	MfaMethodActive   MfaMethodStatus = "active"
	MfaMethodDisabled MfaMethodStatus = "disabled"
)

// KnownMfaMethodTypes are the values accepted in MFA policies
// (allowed_methods). "biometric" is not one: it is not a factor of its own
// (a passkey unlocked with Face ID is a "passkey").
var KnownMfaMethodTypes = []MfaMethodType{
	MfaMethodTOTP,
	MfaMethodPasskey,
	MfaMethodWebAuthn,
	MfaMethodBackupCodes,
}

// IsKnownPolicyMethod tells whether t may appear in an MFA policy.
func IsKnownPolicyMethod(t MfaMethodType) bool {
	for _, k := range KnownMfaMethodTypes {
		if k == t {
			return true
		}
	}
	return false
}

type MfaMethod struct {
	ID              string
	UserID          string
	Type            MfaMethodType
	Name            string // label chosen by the user, display only
	SecretEncrypted string
	CredentialID    string // WebAuthn: base64url credential id
	PublicKey       string // WebAuthn: base64 COSE public key (display only)
	IsDiscoverable  bool
	Status          MfaMethodStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      time.Time
	// LastUsedCounter is the TOTP time step of the last accepted code
	// (anti-replay). Zero for other types.
	LastUsedCounter int64
	// WebAuthnCredential is the full credential record (JSON) the WebAuthn
	// library needs at each login: sign counter, flags, transports...
	WebAuthnCredential string
}

// IsWebAuthn tells whether the factor is a WebAuthn credential (passkey or
// security key).
func (m *MfaMethod) IsWebAuthn() bool {
	return m.Type == MfaMethodPasskey || m.Type == MfaMethodWebAuthn
}

// IsUsable tells whether the factor can answer a challenge right now.
func (m *MfaMethod) IsUsable() bool {
	return m.Status == MfaMethodActive
}
