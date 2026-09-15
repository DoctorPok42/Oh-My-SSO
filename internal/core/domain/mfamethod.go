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
	MfaMethodActive   MfaMethodStatus = "active"
	MfaMethodDisabled MfaMethodStatus = "disabled"
)

type MfaMethod struct {
	ID              string
	UserID          string
	Type            MfaMethodType
	SecretEncrypted string
	CredentialID    string
	PublicKey       string
	IsDiscoverable  bool
	Status          MfaMethodStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      time.Time
}
