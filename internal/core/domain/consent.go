package domain

import "time"

type ConsentStatus string

const (
	ConsentGranted ConsentStatus = "granted"
	ConsentRevoked ConsentStatus = "revoked"
)

// Consent is what a user approved for one client (Step 13): one row per
// (user, client), whose Scopes grow when the client asks for more and the
// user agrees again. A revoked row is kept (history) until the user approves
// the client again, which starts a new list.
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
