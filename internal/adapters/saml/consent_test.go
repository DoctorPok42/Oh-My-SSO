package saml

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Step 13: what the consent page lists for a SAML service provider.
func TestConsentItems(t *testing.T) {
	attrs := &domain.ClientScope{Name: "saml_profile", Description: "Your name, e-mail and groups", Protocol: domain.ClientScopeProtocolSAML2}
	oidcOnly := &domain.ClientScope{Name: "groups", Protocol: domain.ClientScopeProtocolOIDC}
	both := &domain.ClientScope{Name: "employee_id", Protocol: domain.ClientScopeProtocolBoth}
	as := &core.IdentityAssertion{Scopes: []*domain.ClientScope{attrs, oidcOnly, both}}

	persistent := &domain.ClientApp{NameIDFormat: domain.NameIDFormatPersistent}
	require.Equal(t, []string{"saml_profile", "employee_id"}, itemScopes(consentItems(persistent, as)),
		"the attribute scopes; never OIDC-only scopes")

	email := &domain.ClientApp{NameIDFormat: domain.NameIDFormatEmail}
	got := consentItems(email, as)
	require.Equal(t, []string{"email", "saml_profile", "employee_id"}, itemScopes(got),
		"an emailAddress NameID sends the e-mail itself: it is an item")
	require.Equal(t, "Your name, e-mail and groups", got[1].Title)
	require.Equal(t, "employee_id", got[2].Title)
}
