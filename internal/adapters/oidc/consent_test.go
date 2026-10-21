package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Step 13: what the consent page lists for an OIDC request.
func TestConsentItems(t *testing.T) {
	groups := &domain.ClientScope{Name: "groups", Description: "The groups you belong to"}
	noText := &domain.ClientScope{Name: "department"}
	samlOnly := &domain.ClientScope{Name: "saml_profile", Protocol: domain.ClientScopeProtocolSAML2}
	both := &domain.ClientScope{Name: "employee_id", Description: "Your employee number", Protocol: domain.ClientScopeProtocolBoth}

	ar := &authRequest{Scopes: []string{"openid", "email", "profile", "offline_access", "groups"}}
	as := &core.IdentityAssertion{Scopes: []*domain.ClientScope{groups, noText, samlOnly, both}}

	got := consentItems(ar, as)
	require.Equal(t, []string{"email", "profile", "offline_access", "groups", "department", "employee_id"}, itemScopes(got),
		"standard scopes in request order, then the effective ClientScopes (realm defaults included); never openid nor SAML-only scopes")
	require.Equal(t, "Your e-mail address", got[0].Title)
	require.Equal(t, "The groups you belong to", got[3].Title, "a ClientScope is worded by its description")
	require.Equal(t, "department", got[4].Title, "no description: its name")

	// A ClientScope with a standard name is listed once, with the standard words.
	dup := &core.IdentityAssertion{Scopes: []*domain.ClientScope{{Name: "email", Description: "custom"}}}
	got = consentItems(&authRequest{Scopes: []string{"openid", "email"}}, dup)
	require.Len(t, got, 1)
	require.Equal(t, "Your e-mail address", got[0].Title)

	// openid alone: nothing but the identity line of the page.
	require.Empty(t, consentItems(&authRequest{Scopes: []string{"openid"}}, &core.IdentityAssertion{}))
}
