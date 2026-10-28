package domain

import "time"

type LoginAttemptStatus string

const (
	LoginAttemptSuccess LoginAttemptStatus = "success"
	LoginAttemptFailure LoginAttemptStatus = "failure"
)

type LoginAttemptFailureReason string

const (
	LoginFailureInvalidCredentials LoginAttemptFailureReason = "invalid_credentials"
	LoginFailureAccountLocked      LoginAttemptFailureReason = "account_locked"
	LoginFailureMfaFailed          LoginAttemptFailureReason = "mfa_failed"
	LoginFailureUnknownAccount     LoginAttemptFailureReason = "unknown_account"
	LoginFailureTimeoutActive      LoginAttemptFailureReason = "timeout_active"
	LoginFailureAccessDenied       LoginAttemptFailureReason = "access_denied"
)

// LoginFailurePasskeyRejected: a sign-in without password whose passkey or
// security key answer was refused (bad signature, no user verification,
// cloned authenticator...).
const LoginFailurePasskeyRejected LoginAttemptFailureReason = "passkey_rejected"

type LoginAttempt struct {
	ID            string
	RealmID       string
	UserID        string
	Identifier    string
	IPAddress     string
	UserAgent     string
	Status        LoginAttemptStatus
	FailureReason LoginAttemptFailureReason
	CreatedAt     time.Time
}
