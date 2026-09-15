package domain

import "time"

type ConsentStatus string

const (
	ConsentGranted ConsentStatus = "granted"
	ConsentRevoked ConsentStatus = "revoked"
)

type Consent struct {
	ID          string
	UserID      string
	ClientRefID string
	Scopes      []string
	Status      ConsentStatus
	GrantedAt   time.Time
	RevokedAt   time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
