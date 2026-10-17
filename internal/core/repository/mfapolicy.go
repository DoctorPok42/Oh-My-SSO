package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// MfaPolicyRepository stores the per-role MFA policies.
type MfaPolicyRepository interface {
	// Upsert creates the policy of the role, or replaces every field of the
	// existing one (one policy per role).
	Upsert(ctx context.Context, p UpsertMfaPolicyParams) (*domain.MfaPolicy, error)
	GetByRole(ctx context.Context, roleID string) (*domain.MfaPolicy, error)
	ListByRealm(ctx context.Context, realmID string) ([]*domain.MfaPolicy, error)
	ListByRoleIDs(ctx context.Context, roleIDs []string) ([]*domain.MfaPolicy, error)
	DeleteByRole(ctx context.Context, roleID string) error
}

type UpsertMfaPolicyParams struct {
	RealmID                   string
	RoleID                    string
	ManagedBy                 domain.MfaPolicyManagedBy // empty: ui
	Required                  bool
	AllowedMethods            []domain.MfaMethodType
	EnrollmentGraceDays       int
	StepUpForSensitiveActions bool
	RequiredSince             time.Time // zero: none
}
