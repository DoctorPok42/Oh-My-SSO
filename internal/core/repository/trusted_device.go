package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// TrustedDeviceRepository stores "Don't ask again on this device"
// (domain.TrustedDevice), one row per user and device.
type TrustedDeviceRepository interface {
	// Put trusts a device for a user: it creates the row, or replaces the
	// existing one (a new period starts).
	Put(ctx context.Context, p PutTrustedDeviceParams) (*domain.TrustedDevice, error)
	// Get returns the trust of a user on a device, expired or not
	// (ErrNotFound when there is none).
	Get(ctx context.Context, userID, deviceHash string) (*domain.TrustedDevice, error)
	// MarkUsed records a sign-in that skipped the second factor.
	MarkUsed(ctx context.Context, id string, at time.Time, ip, userAgent string) error
	// ListByUser returns the devices of a user that are still trusted at
	// now, most recently created first.
	ListByUser(ctx context.Context, userID string, now time.Time) ([]*domain.TrustedDevice, error)
	// Delete removes one trust (ErrNotFound when it does not exist).
	Delete(ctx context.Context, id string) error
	// DeleteByUser removes every trust of a user; DeleteByDevice the one of
	// a device. Both return how many rows they removed.
	DeleteByUser(ctx context.Context, userID string) (int, error)
	DeleteByDevice(ctx context.Context, userID, deviceHash string) (int, error)
	// DeleteExpired removes the trusts of a user that ended before now.
	DeleteExpired(ctx context.Context, userID string, now time.Time) (int, error)
}

type PutTrustedDeviceParams struct {
	RealmID    string
	UserID     string
	DeviceHash string
	IPAddress  string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}
