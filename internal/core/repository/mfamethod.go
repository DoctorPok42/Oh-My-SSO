package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type MfaMethodRepository interface {
	Create(ctx context.Context, p CreateMfaMethodParams) (*domain.MfaMethod, error)
	GetByID(ctx context.Context, id string) (*domain.MfaMethod, error)
	ListByUser(ctx context.Context, userID string) ([]*domain.MfaMethod, error)
	Update(ctx context.Context, id string, p UpdateMfaMethodParams) (*domain.MfaMethod, error)
	MarkUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error

	// ActivateTOTP turns a pending TOTP into the user's active one, in a
	// single transaction: any other active TOTP of the user is deleted
	// first (new phone replaces the old one). counter is the time step of
	// the code that confirmed the enrollment: it can never be reused.
	// Returns ErrNotFound if the method is not a pending TOTP anymore.
	ActivateTOTP(ctx context.Context, id string, counter int64, at time.Time) (*domain.MfaMethod, error)

	// ConsumeTOTPCounter records that the code of time step `counter` was
	// accepted. It only succeeds (true) if counter is strictly greater than
	// the stored one, atomically: two requests replaying the same code at
	// the same time cannot both succeed.
	ConsumeTOTPCounter(ctx context.Context, id string, counter int64, at time.Time) (bool, error)

	// DeletePendingByUser removes the user's unfinished enrollments of a type.
	DeletePendingByUser(ctx context.Context, userID string, t domain.MfaMethodType) (int, error)

	// DeleteByUser removes every factor of the user (admin MFA reset).
	DeleteByUser(ctx context.Context, userID string) (int, error)

	// UpdateWebAuthnCredential stores the credential record returned by a
	// successful WebAuthn login (new sign counter, backup state...).
	UpdateWebAuthnCredential(ctx context.Context, id string, credentialJSON string, at time.Time) error
}

type CreateMfaMethodParams struct {
	UserID          string
	Type            domain.MfaMethodType
	Name            string
	Status          domain.MfaMethodStatus // empty: active
	SecretEncrypted string
	CredentialID    string
	PublicKey       string
	IsDiscoverable  bool
	// WebAuthnCredential: full credential record (JSON), passkeys only.
	WebAuthnCredential string
}

type UpdateMfaMethodParams struct {
	Status *domain.MfaMethodStatus
	Name   *string
}
