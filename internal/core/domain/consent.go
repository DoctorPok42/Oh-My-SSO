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
	GrantedAt   time.Time // first approval, or the approval after a revocation
	RevokedAt   time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time // last change, e.g. scopes added
}

// IsGranted reports whether the consent is in force.
func (c *Consent) IsGranted() bool {
	return c != nil && c.Status == ConsentGranted
}
