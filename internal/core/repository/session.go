package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, p CreateSessionParams) (*domain.Session, error)
	GetByID(ctx context.Context, id string) (*domain.Session, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]*domain.Session, error)
	// ListRecentByUser returns the user's sessions (any status) created
	// since the given time, newest first, at most limit. Step 12 compares a
	// new sign-in with them (known device, usual hours and places).
	ListRecentByUser(ctx context.Context, userID string, since time.Time, limit int) ([]*domain.Session, error)
	Touch(ctx context.Context, id string, at time.Time) error
	MarkExpired(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string, reason domain.SessionRevokedReason) error
	// MarkMFAVerified records a successful second-factor verification on an
	// active session. ErrNotFound if the session is not active anymore.
	MarkMFAVerified(ctx context.Context, id string, method string, at time.Time) error
	RevokeAllByUser(ctx context.Context, userID string, reason domain.SessionRevokedReason) ([]*domain.Session, error)
	Delete(ctx context.Context, id string) error
}

type CreateSessionParams struct {
	// CreatedAt (Step 14): when the session starts; also its first
	// last_activity_at. Zero: the database's clock. The session service sets
	// it from its own clock, like expires_at, so every timestamp of a session
	// comes from the same clock.
	CreatedAt         time.Time
	RealmID           string
	UserID            string
	ExpiresAt         time.Time
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	MFAVerified       bool
	MFAMethodType     string
	MFAVerifiedAt     time.Time
	AuthMethod        string
	TokenHash         string
}
