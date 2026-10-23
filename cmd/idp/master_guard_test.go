package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGuardMasterRealm(t *testing.T) {
	refused := []string{
		"mfa reset --realm master --user admin --reason x",
		"mfa reset --realm=master --user admin",
		"mfa reset -realm MASTER --user admin",
		"mfa policy set-realm --realm master --required=false",
		"oidc clients rotate-secret --realm master --client-id sso-admin",
		"oidc clients create --realm master --client-id evil",
		"saml clients create --realm master --metadata-url x",
		"keys rotate --realm master",
		"users unlock --realm master --user admin",
		"settings set --realm master --notification-email=false",
		"consents revoke --realm master --user a --client b",
		"dev seed --realm master",
	}
	for _, cmd := range refused {
		require.Error(t, guardMasterRealm(strings.Fields(cmd)), cmd)
	}

	allowed := []string{
		"",
		"serve",
		"keys list --realm master",
		"mfa list --realm master --user admin",
		"mfa policy show --realm master",
		"oidc clients list --realm master",
		"saml clients list --realm master",
		"consents list --realm master --user admin",
		"users status --realm master --user admin",
		"settings show --realm master",
		// Other realms: nothing changes.
		"mfa reset --realm demo --user alice --reason lost",
		"keys rotate --realm demo",
		"dev seed",
		"mail test --to a@b.c",
		// A realm whose name only contains "master".
		"keys rotate --realm masterclass",
	}
	for _, cmd := range allowed {
		require.NoError(t, guardMasterRealm(strings.Fields(cmd)), cmd)
	}
}
