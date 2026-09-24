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
	Touch(ctx context.Context, id string, at time.Time) error
	MarkExpired(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string, reason domain.SessionRevokedReason) error
	RevokeAllByUser(ctx context.Context, userID string, reason domain.SessionRevokedReason) ([]*domain.Session, error)
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
	TokenHash         string
}
