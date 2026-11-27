package domain

import "time"

// ApiResource is an API that accepts the realm's access tokens (RFC 8707).
// A token asked for it with the "resource" parameter has its Identifier as
// "aud", and only its scopes besides the standard OIDC ones.
type ApiResource struct {
	ID          string
	RealmID     string
	Identifier  string // absolute URI, never changes
	Name        string
	Description string
	// Scopes: the OIDC client scopes the API defines.
	Scopes    []*ClientScope
	CreatedAt time.Time
	UpdatedAt time.Time
}
