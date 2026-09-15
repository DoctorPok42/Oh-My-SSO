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

type LoginAttempt struct {
	ID            string
	Identifier    string
	IPAddress     string
	UserAgent     string
	Status        LoginAttemptStatus
	FailureReason LoginAttemptFailureReason
	CreatedAt     time.Time
}
