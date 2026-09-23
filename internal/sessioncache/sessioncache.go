package sessioncache

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type Entry struct {
	SessionID      string               `json:"sid"`
	RealmID        string               `json:"rid"`
	UserID         string               `json:"uid"`
	Status         domain.SessionStatus `json:"st"`
	ExpiresAt      time.Time            `json:"exp"`
	LastActivityAt time.Time            `json:"la"`
	MFAVerified    bool                 `json:"mfa"`
}

type Cache interface {
	Get(ctx context.Context, tokenHash string) (*Entry, bool, bool, error)
	Fill(ctx context.Context, tokenHash string, e Entry, ttl time.Duration) error
	Refresh(ctx context.Context, tokenHash string, e Entry, ttl time.Duration) error
	MarkRevoked(ctx context.Context, tokenHash string, ttl time.Duration) error
}
