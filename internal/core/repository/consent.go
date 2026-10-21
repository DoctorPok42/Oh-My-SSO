package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type ConsentRepository interface {
	// Create fails with ErrConflict when the user already has a row for this
	// client (UNIQUE (user_id, client_ref_id)): Update that row instead.
	Create(ctx context.Context, p CreateConsentParams) (*domain.Consent, error)
	// GetByID and GetByUserAndClient return ErrNotFound when there is no row.
	GetByID(ctx context.Context, id string) (*domain.Consent, error)
	GetByUserAndClient(ctx context.Context, userID, clientRefID string) (*domain.Consent, error)
	// ListByUser returns every consent of a user, granted or revoked, most
	// recently changed first (Step 13: `idp consents list`, later the
	// "connected applications" page of the user panel).
	ListByUser(ctx context.Context, userID string) ([]*domain.Consent, error)
	Update(ctx context.Context, id string, p UpdateConsentParams) (*domain.Consent, error)
	Revoke(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

type CreateConsentParams struct {
	UserID      string
	ClientRefID string
	Scopes      []string
}

// UpdateConsentParams: nil fields are left unchanged.
type UpdateConsentParams struct {
	Scopes []string
	// Step 13: approving a client again after a revocation sets the status
	// back to granted with a new GrantedAt, and clears RevokedAt.
	Status         *domain.ConsentStatus
	GrantedAt      *time.Time
	ClearRevokedAt bool
}
