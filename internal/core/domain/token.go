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
}
