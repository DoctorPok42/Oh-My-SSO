package domain

import "time"

type TokenType string

const (
	TokenAccessToken  TokenType = "access_token"
	TokenRefreshToken TokenType = "refresh_token"
	TokenIDToken      TokenType = "id_token"
)

type Token struct {
	ID          string
	SessionID   string
	ClientRefID string
	Type        TokenType
	JTI         string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Revoked     bool
	Scopes      []string

	// TokenHash is the SHA-256 of an opaque token (refresh tokens). Empty
	// for JWT access tokens, which are identified by JTI.
	TokenHash string
	// FamilyID groups the tokens born from one authorization (code exchange
	// and every refresh after it), to revoke them together.
	FamilyID string
	// UsedAt is set when a refresh token was exchanged (rotation). Zero if
	// never used.
	UsedAt time.Time
}

// IsUsed reports whether a refresh token was already exchanged.
func (t Token) IsUsed() bool { return !t.UsedAt.IsZero() }
