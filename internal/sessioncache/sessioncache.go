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
	CreatedAt      time.Time            `json:"cat"`
	Status         domain.SessionStatus `json:"st"`
	ExpiresAt      time.Time            `json:"exp"`
	LastActivityAt time.Time            `json:"la"`
	MFAVerified    bool                 `json:"mfa"`
	MFAMethodType  string               `json:"mfat,omitempty"`
	AuthMethod     string               `json:"am"`
}

type Result struct {
	Entry   *Entry
	Revoked bool
}

type Cache interface {
	Get(ctx context.Context, tokenHash string) (Result, error)
	Fill(ctx context.Context, tokenHash string, e Entry, ttl time.Duration) error
	Refresh(ctx context.Context, tokenHash string, e Entry, ttl time.Duration) error
	MarkRevoked(ctx context.Context, tokenHash string, ttl time.Duration) error
}

func EntryFromSession(s *domain.Session) Entry {
	return Entry{
		SessionID:      s.ID,
		RealmID:        s.RealmID,
		UserID:         s.UserID,
		CreatedAt:      s.CreatedAt,
		Status:         s.Status,
		ExpiresAt:      s.ExpiresAt,
		LastActivityAt: s.LastActivityAt,
		MFAVerified:    s.MFAVerified,
		MFAMethodType:  s.MFAMethodType,
		AuthMethod:     s.AuthMethod,
	}
}

func (e Entry) ToSession(tokenHash string) *domain.Session {
	return &domain.Session{
		ID:             e.SessionID,
		TokenHash:      tokenHash,
		RealmID:        e.RealmID,
		UserID:         e.UserID,
		CreatedAt:      e.CreatedAt,
		Status:         e.Status,
		ExpiresAt:      e.ExpiresAt,
		LastActivityAt: e.LastActivityAt,
		MFAVerified:    e.MFAVerified,
		MFAMethodType:  e.MFAMethodType,
		AuthMethod:     e.AuthMethod,
	}
}
