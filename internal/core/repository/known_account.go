package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// KnownAccountRepository stores the accounts of "Pick an account", per
// device (domain.KnownAccount).
type KnownAccountRepository interface {
	// Touch records a sign-in of userID on a device: it creates the row,
	// or moves its last_used_at to at.
	Touch(ctx context.Context, realmID, deviceHash, userID string, at time.Time) (*domain.KnownAccount, error)
	// ListByDevice returns the accounts of a device in a realm, most
	// recently used first.
	ListByDevice(ctx context.Context, realmID, deviceHash string) ([]*domain.KnownAccount, error)
	// GetByID returns ErrNotFound for an unknown id.
	GetByID(ctx context.Context, id string) (*domain.KnownAccount, error)
	// Delete returns ErrNotFound when the row does not exist (any more).
	Delete(ctx context.Context, id string) error
	// Trim keeps the keep most recently used accounts of a device and
	// deletes the others. It returns how many rows it deleted.
	Trim(ctx context.Context, realmID, deviceHash string, keep int) (int, error)
	// Find returns the row of userID on a device, ErrNotFound if the device
	// does not remember the account.
	Find(ctx context.Context, realmID, deviceHash, userID string) (*domain.KnownAccount, error)
	// SetLastMethods sets the fields of p that are not nil on the row of
	// userID on a device. No row: nothing to do (false, nil).
	SetLastMethods(ctx context.Context, realmID, deviceHash, userID string, p LastMethodsParams) (bool, error)
}

// LastMethodsParams: how the user signed in on a device (Step 18e).
type LastMethodsParams struct {
	LastMethod       *string
	LastSecondFactor *string
}
