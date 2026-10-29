package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type TimeoutRepository interface {
	Create(ctx context.Context, p CreateTimeoutParams) (*domain.Timeout, error)
	// GetByID returns ErrNotFound when there is no such timeout.
	GetByID(ctx context.Context, id string) (*domain.Timeout, error)
	// ListByRealm returns a page of a realm's timeouts, latest start first,
	// and how many match in all (-1 with page.NoTotal).
	ListByRealm(ctx context.Context, realmID string, f TimeoutFilter, page Page) ([]*domain.Timeout, int, error)
	// InForce returns the timeouts in force at `at` that target userID
	// directly, one of the groups userID belongs to, or clientRef. Empty
	// ids are skipped. One query, at every sign-in and token issuance.
	InForce(ctx context.Context, userID, clientRef string, at time.Time) ([]*domain.Timeout, error)
	// Update changes the reason and/or the end of a timeout that is not
	// lifted. ErrNotFound when missing or lifted meanwhile.
	Update(ctx context.Context, id string, p UpdateTimeoutParams) (*domain.Timeout, error)
	// Lift ends a timeout at `at` (ends_at and lifted_at), unless it is
	// already lifted or ended: false then (a single conditional UPDATE).
	Lift(ctx context.Context, id, by string, at time.Time) (bool, error)

	// ListToEnforce returns, oldest first, the timeouts in force at `at`
	// whose targets were never signed out (at most limit).
	ListToEnforce(ctx context.Context, at time.Time, limit int) ([]*domain.Timeout, error)
	// MarkEnforced records the sign-out of a timeout's targets. false: it
	// was already recorded (another process got there first).
	MarkEnforced(ctx context.Context, id string, at time.Time) (bool, error)
	// ClearEnforced undoes MarkEnforced after a failed sign-out, so that the
	// enforcer tries again.
	ClearEnforced(ctx context.Context, id string) error
}

type CreateTimeoutParams struct {
	RealmID    string
	TargetType domain.TimeoutTargetType
	TargetID   string
	StartsAt   time.Time
	EndsAt     time.Time // zero: no end
	Reason     string
	CreatedBy  string
}

// TimeoutFilter narrows ListByRealm.
type TimeoutFilter struct {
	// Current: true keeps the timeouts that are or will be in force at At
	// (scheduled and active), false the others (ended, lifted); nil keeps
	// every timeout.
	Current *bool
	At      time.Time
}

type UpdateTimeoutParams struct {
	Reason *string
	// EndsAt: nil leaves the end as it is; a zero time removes it (no end).
	EndsAt *time.Time
}
