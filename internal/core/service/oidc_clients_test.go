package service_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/service"
)

func TestNormalizeOIDCClient(t *testing.T) {
	base := func(mod func(*service.OIDCClientInput)) service.OIDCClientInput {
		in := service.OIDCClientInput{ClientID: "payroll", RedirectURIs: []string{"https://payroll.example.com/cb"}}
		if mod != nil {
			mod(&in)
		}
		return in
	}

	t.Run("defaults", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(nil))
		require.NoError(t, err)
		require.Equal(t, "payroll", got.Name)
		require.Equal(t, []string{"openid"}, got.AllowedScopes, "openid is always allowed")
		require.Equal(t, []string{"authorization_code", "refresh_token"}, got.GrantTypes)
		require.Equal(t, "client_secret_basic", got.AuthMethod)
		require.Equal(t, []string{}, got.PostLogoutRedirectURIs)
	})

	t.Run("standard and custom scopes", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(func(in *service.OIDCClientInput) {
			in.Scopes = []string{"profile", "email", "groups", "profile", " "}
		}))
		require.NoError(t, err)
		require.Equal(t, []string{"openid", "profile", "email", "groups"}, got.AllowedScopes)
		require.Equal(t, []string{"groups"}, got.CustomScopes, "only custom scopes need a ClientScope row")
	})

	t.Run("public client", func(t *testing.T) {
		got, err := service.NormalizeOIDCClient(base(func(in *service.OIDCClientInput) {
			in.Public = true
			in.RedirectURIs = []string{"http://127.0.0.1:5173/cb", "com.example.app:/oauth2redirect"}
		}))
		require.NoError(t, err)
		require.Equal(t, "none", got.AuthMethod)
	})

	refused := map[string]func(*service.OIDCClientInput){
		"bad client_id":               func(in *service.OIDCClientInput) { in.ClientID = "has space" },
		"no redirect URI":             func(in *service.OIDCClientInput) { in.RedirectURIs = nil },
		"relative URI":                func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"/cb"} },
		"fragment":                    func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"https://a.example/cb#x"} },
		"wildcard":                    func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"https://*.example.com/cb"} },
		"http on a real host":         func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"http://app.example.com/cb"} },
		"javascript URI":              func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"javascript:alert(1)"} },
		"custom scheme, confidential": func(in *service.OIDCClientInput) { in.RedirectURIs = []string{"com.example.app:/cb"} },
		"custom scheme not reverse-DNS": func(in *service.OIDCClientInput) {
			in.Public = true
			in.RedirectURIs = []string{"myapp:/cb"}
		},
		"implicit grant": func(in *service.OIDCClientInput) { in.GrantTypes = []string{"implicit"} },
		"password grant": func(in *service.OIDCClientInput) { in.GrantTypes = []string{"password"} },
		"refresh only":   func(in *service.OIDCClientInput) { in.GrantTypes = []string{"refresh_token"} },
		"offline_access without refresh": func(in *service.OIDCClientInput) {
			in.GrantTypes = []string{"authorization_code"}
			in.Scopes = []string{"offline_access"}
		},
		"public without PKCE":   func(in *service.OIDCClientInput) { in.Public = true; in.DisablePKCE = true },
		"public with a secret":  func(in *service.OIDCClientInput) { in.Public = true; in.Secret = strings.Repeat("x", 40) },
		"short supplied secret": func(in *service.OIDCClientInput) { in.Secret = "too-short" },
		"unknown auth method":   func(in *service.OIDCClientInput) { in.TokenEndpointAuthMethod = "private_key_jwt" },
		"bad post-logout URI":   func(in *service.OIDCClientInput) { in.PostLogoutRedirectURIs = []string{"http://evil.example/"} },
	}
	for name, mod := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			_, err := service.NormalizeOIDCClient(base(mod))
			require.ErrorIs(t, err, service.ErrInvalidClientConfig)
		})
	}
}
