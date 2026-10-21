package repository

import (
	"context"
	"time"

	"sso.internal/sso/internal/core/domain"
)

type TokenRepository interface {
	Create(ctx context.Context, p CreateTokenParams) (*domain.Token, error)
	GetByID(ctx context.Context, id string) (*domain.Token, error)
	GetByJTI(ctx context.Context, jti string) (*domain.Token, error)
	// GetByHash finds an opaque token (refresh token) by its SHA-256.
	GetByHash(ctx context.Context, tokenHash string) (*domain.Token, error)
	ListBySession(ctx context.Context, sessionID string) ([]*domain.Token, error)
	Revoke(ctx context.Context, id string) error
	// MarkUsed atomically marks a refresh token as exchanged. It returns
	// false, nil when the token was already used or revoked: only one of two
	// concurrent exchanges of the same refresh token can ever win.
	MarkUsed(ctx context.Context, id string, at time.Time) (bool, error)
	// RevokeFamily revokes every token of a family and returns how many
	// were still active.
	RevokeFamily(ctx context.Context, familyID string) (int, error)
	// RevokeByUserAndClient revokes the access, refresh and ID tokens that
	// one client holds for one user, in all of the user's sessions, and
	// returns how many were still active (Step 13: a revoked consent). The
	// SAML session participant records stay: Single Logout still needs them.
	RevokeByUserAndClient(ctx context.Context, userID, clientRefID string) (int, error)
	Delete(ctx context.Context, id string) error
}

type CreateTokenParams struct {
	SessionID   string
	ClientRefID string
	Type        domain.TokenType
	JTI         string
	ExpiresAt   time.Time
	Scopes      []string
	TokenHash   string // opaque tokens only
	FamilyID    string
	// Subject / SubjectFormat: session participants only (Step 11).
	Subject       string
	SubjectFormat string
}
