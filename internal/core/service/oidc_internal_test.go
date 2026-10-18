package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
)

func TestFilterRequestedScopes_DefaultScopes(t *testing.T) {
	groups := &domain.ClientScope{Name: "groups"}
	dept := &domain.ClientScope{Name: "department", IsDefault: true}
	effective := []*domain.ClientScope{groups, dept}

	require.Equal(t, effective, filterRequestedScopes(effective, nil), "no request: everything")
	require.Equal(t, []*domain.ClientScope{groups, dept}, filterRequestedScopes(effective, []string{"openid", "groups"}))
	require.Equal(t, []*domain.ClientScope{dept}, filterRequestedScopes(effective, []string{"openid"}),
		"is_default is kept without being requested")
	require.Empty(t, filterRequestedScopes([]*domain.ClientScope{groups}, []string{"openid", "department"}),
		"is_default never grants: the scope must be effective (RBAC) first")
}

func TestUserAttributes(t *testing.T) {
	u := &domain.User{
		Username: "alice", Email: "alice@example.com",
		UpdatedAt: time.Unix(1_700_000_000, 0),
		Profile:   map[string]interface{}{"given_name": "Alice", "email_verified": true},
	}
	got := userAttributes(u, []string{"admins"}, nil)
	require.Equal(t, map[string]any{
		"username":               "alice",
		"email":                  "alice@example.com",
		"updated_at":             int64(1_700_000_000),
		"profile.given_name":     "Alice",
		"profile.email_verified": true,
		"groups":                 []string{"admins"},
		"roles":                  []string{},
	}, got)
}

func TestClientSecret(t *testing.T) {
	secret, hash := NewClientSecret()
	require.Len(t, secret, 43, "32 random bytes, base64url")
	require.Equal(t, "sha256:", hash[:7])
	require.True(t, verifyClientSecret(secret, hash))
	require.False(t, verifyClientSecret(secret[:42], hash))
	require.False(t, verifyClientSecret("", hash))
	require.False(t, verifyClientSecret(secret, ""), "no hash stored: never authenticated")
	require.False(t, verifyClientSecret(secret, "plain:"+secret), "unknown scheme: refused")
	other, _ := NewClientSecret()
	require.NotEqual(t, secret, other)
}
