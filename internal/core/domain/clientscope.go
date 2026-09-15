package domain

import "time"

type ClientScopeProtocol string

const (
	ClientScopeProtocolOIDC  ClientScopeProtocol = "oidc"
	ClientScopeProtocolSAML2 ClientScopeProtocol = "saml2"
	ClientScopeProtocolBoth  ClientScopeProtocol = "both"
)

type ClientScope struct {
	ID           string
	RealmID      string
	Name         string
	Description  string
	Protocol     ClientScopeProtocol
	IsDefault    bool
	ClaimMappers []map[string]interface{}
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
