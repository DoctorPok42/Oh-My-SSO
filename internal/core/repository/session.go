package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, p CreateSessionParams) (*domain.Session, error)
	GetByID(ctx context.Context, id string) (*domain.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]*domain.Session, error)
	Touch(ctx context.Context, id string) error // Keep-alive
	Revoke(ctx context.Context, id string, reason domain.SessionRevokedReason) error
	Delete(ctx context.Context, id string) error
}

type CreateSessionParams struct {
	RealmID           string
	UserID            string
	ExpiresAt         time.Time
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	MFAVerified       bool
	MFAMethodType     string
	AuthMethod        string
}
