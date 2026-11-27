package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// fakeAPIResources: only the lookup the core uses.
type fakeAPIResources struct {
	repository.ApiResourceRepository
	list []*domain.ApiResource
}

func (f *fakeAPIResources) GetByRealmAndIdentifier(_ context.Context, realmID, identifier string) (*domain.ApiResource, error) {
	for _, r := range f.list {
		if r.RealmID == realmID && r.Identifier == identifier {
			return r, nil
		}
	}
	return nil, repository.ErrNotFound
}

const (
	ordersAPI  = "https://orders.example.com"
	billingAPI = "https://billing.example.com"
)

// withAPIs: "orders" defines "groups" (a scope the fixture's clients may
// ask for), "billing" defines a scope no client holds.
func withAPIs(f *coreFixture) {
	f.resources.list = []*domain.ApiResource{
		{ID: "r-orders", RealmID: realmA, Identifier: ordersAPI, Scopes: []*domain.ClientScope{{ID: "s-groups", Name: "groups"}}},
		{ID: "r-billing", RealmID: realmA, Identifier: billingAPI, Scopes: []*domain.ClientScope{{ID: "s-billing", Name: "billing"}}},
	}
}

func TestIdentityCore_CheckResources(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	withAPIs(f)

	// The client's scopes, as the adapter passes them: "groups" only.
	held := []*domain.ClientScope{{ID: "s-groups", RealmID: realmA, Name: "groups"}}
	got, err := f.core.CheckResources(ctx, realmA, held, []string{ordersAPI, ordersAPI})
	require.NoError(t, err)
	require.Equal(t, []string{ordersAPI}, got, "duplicates dropped")

	got, err = f.core.CheckResources(ctx, realmA, held, nil)
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = f.core.CheckResources(ctx, realmA, held, []string{"https://unknown.example.com"})
	require.ErrorIs(t, err, core.ErrInvalidTarget)
	_, err = f.core.CheckResources(ctx, realmA, held, []string{ordersAPI, billingAPI})
	require.ErrorIs(t, err, core.ErrInvalidTarget, "the client holds none of billing's scopes")
}

func TestIdentityCore_TokensForAnAPI(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	withAPIs(f)
	sess := f.aliceSession(t)
	grant := []string{"openid", "email", "groups", "reports"}

	t.Run("the access token is for the API, the refresh token keeps the grant", func(t *testing.T) {
		out, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.Session.ID, ClientRef: clientOIDC,
			Scopes: grant, Resources: []string{ordersAPI}, WithRefreshToken: true})
		require.NoError(t, err)
		require.Equal(t, []string{ordersAPI}, out.Access.Audience)
		require.Equal(t, []string{"openid", "email", "groups"}, out.Access.Scopes, "reports is no scope of the API")
		require.Equal(t, []string{ordersAPI}, out.Refresh.Audience)
		require.Equal(t, grant, out.Refresh.Scopes)

		t.Run("a resource outside the grant does not consume the refresh token", func(t *testing.T) {
			_, err := f.core.RotateRefreshToken(ctx, out.RefreshToken, clientOIDC, nil, []string{billingAPI})
			require.ErrorIs(t, err, core.ErrInvalidTarget)
			require.False(t, f.tokens.get(out.Refresh.JTI).IsUsed())

			next, err := f.core.RotateRefreshToken(ctx, out.RefreshToken, clientOIDC, nil, []string{ordersAPI})
			require.NoError(t, err)
			require.Equal(t, []string{ordersAPI}, next.Access.Audience)
			require.Equal(t, []string{ordersAPI}, next.Refresh.Audience)
		})
	})

	t.Run("without resource the token is for the client, as before", func(t *testing.T) {
		out, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.Session.ID, ClientRef: clientOIDC, Scopes: grant})
		require.NoError(t, err)
		require.Empty(t, out.Access.Audience)
		require.Equal(t, grant, out.Access.Scopes)
	})

	t.Run("the token request may only narrow the resources (RFC 8707, section 2.2)", func(t *testing.T) {
		_, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.Session.ID, ClientRef: clientOIDC,
			Scopes: grant, Resources: []string{ordersAPI}, Audience: []string{billingAPI}})
		require.ErrorIs(t, err, core.ErrInvalidTarget)
	})

	t.Run("an API deleted since the grant", func(t *testing.T) {
		out, err := f.core.IssueTokens(ctx, core.TokenRequest{SessionID: sess.Session.ID, ClientRef: clientOIDC,
			Scopes: grant, Resources: []string{ordersAPI}, WithRefreshToken: true})
		require.NoError(t, err)
		saved := f.resources.list
		f.resources.list = nil
		defer func() { f.resources.list = saved }()
		_, err = f.core.RotateRefreshToken(ctx, out.RefreshToken, clientOIDC, nil, nil)
		require.ErrorIs(t, err, core.ErrInvalidTarget)
	})
}

func TestIdentityCore_AuthenticateClient_PrivateKeyJWT(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	c := f.clients.byID[clientOIDC]
	c.ClientSecretHash = service.HashClientSecret("an-old-secret-from-before-the-switch")
	require.NoError(t, f.core.AuthenticateClient(ctx, clientOIDC, "an-old-secret-from-before-the-switch"))

	c.TokenEndpointAuthMethod = service.AuthMethodPrivateKeyJWT
	require.ErrorIs(t, f.core.AuthenticateClient(ctx, clientOIDC, "an-old-secret-from-before-the-switch"),
		core.ErrInvalidClientSecret, "a private_key_jwt client never authenticates with a secret")
}
