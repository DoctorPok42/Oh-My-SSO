package httpserver_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// user (list, revoke one, revoke all, signed out everywhere).
func TestAdmin_Integration_TrustedDevices(t *testing.T) {
	e := setupAdminTestEnv(t)
	ctx := context.Background()

	res, err := e.admin.Bootstrap(ctx, service.BootstrapInput{AdminEmail: "root@example.test",
		AdminConsoleURL: adminConsoleURL, Actor: "cli:test@host"})
	require.NoError(t, err)
	e.activate(t, res.ActivationURL)
	console := &oauth2.Config{ClientID: "sso-admin", ClientSecret: res.ClientSecret,
		RedirectURL: adminConsoleURL + "/auth/callback", Scopes: []string{"openid", "profile", "email", "offline_access"},
		Endpoint: oauth2.Endpoint{AuthURL: e.idp.URL + "/r/master/oidc/authorize", TokenURL: e.idp.URL + "/r/master/oidc/token",
			AuthStyle: oauth2.AuthStyleInHeader}}
	var secret string
	at := e.signIn(t, console, "root", &secret).AccessToken

	status, out := e.call(t, at, http.MethodPost, "/api/v1/realms", map[string]any{"name": "demo"})
	require.Equal(t, http.StatusCreated, status, "%v", out)
	demo, err := e.admin.RealmByName(ctx, "demo")
	require.NoError(t, err)

	t.Run("the realm setting", func(t *testing.T) {
		status, out := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/mfa-policies", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, true, out["trusted_devices_enabled"], "on by default")
		require.EqualValues(t, 30, out["trusted_device_days"])

		status, out = e.call(t, at, http.MethodPut, "/api/v1/realms/demo/mfa-policies/realm", map[string]any{"trusted_device_days": 7})
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.EqualValues(t, 7, out["trusted_device_days"])
		status, out = e.call(t, at, http.MethodPut, "/api/v1/realms/demo/mfa-policies/realm", map[string]any{"trusted_device_days": 120})
		require.Equal(t, http.StatusBadRequest, status, "%v", out)

		status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/master/mfa-policies", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.Equal(t, false, out["trusted_devices_enabled"], "off in master")
		status, out = e.call(t, at, http.MethodPut, "/api/v1/realms/master/mfa-policies/realm", map[string]any{"trusted_devices_enabled": true})
		require.Equal(t, http.StatusConflict, status, "%v", out)
		require.Equal(t, "system_realm", out["error"])
	})

	carol, err := e.users.Create(ctx, repository.CreateUserParams{RealmID: demo.ID, Username: "carol",
		Email: "carol@demo.test", Status: domain.UserActive})
	require.NoError(t, err)
	trust := func(n int) []string {
		now := e.clock.Now()
		var ids []string
		for i := 0; i < n; i++ {
			d, err := e.devices.Put(ctx, repository.PutTrustedDeviceParams{RealmID: demo.ID, UserID: carol.ID,
				DeviceHash: fmt.Sprintf("device-%d-%d", now.UnixNano(), i), IPAddress: "203.0.113.7",
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
				CreatedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour)})
			require.NoError(t, err)
			ids = append(ids, d.ID)
		}
		return ids
	}
	devicesOf := func(t *testing.T) []any {
		t.Helper()
		status, out := e.call(t, at, http.MethodGet, "/api/v1/realms/demo/users/"+carol.ID, nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		return out["trusted_devices"].([]any)
	}
	userPath := "/api/v1/realms/demo/users/" + carol.ID

	t.Run("listed with a readable name, revoked one by one or all", func(t *testing.T) {
		ids := trust(2)
		list := devicesOf(t)
		require.Len(t, list, 2)
		first := list[0].(map[string]any)
		require.Equal(t, "Firefox on Windows", first["device"])
		require.Equal(t, "203.0.113.7", first["ip_address"])

		status, out := e.call(t, at, http.MethodDelete, userPath+"/trusted-devices/"+ids[0], nil)
		require.Equal(t, http.StatusNoContent, status, "%v", out)
		status, _ = e.call(t, at, http.MethodDelete, userPath+"/trusted-devices/"+ids[0], nil)
		require.Equal(t, http.StatusNotFound, status, "already gone")
		require.Len(t, devicesOf(t), 1)

		status, out = e.call(t, at, http.MethodDelete, userPath+"/trusted-devices", nil)
		require.Equal(t, http.StatusNoContent, status, "%v", out)
		require.Empty(t, devicesOf(t))

		status, out = e.call(t, at, http.MethodGet, "/api/v1/realms/demo/audit-logs?action=admin.trusted_device.revoke", nil)
		require.Equal(t, http.StatusOK, status, "%v", out)
		require.EqualValues(t, 1, out["total"])
	})

	t.Run("signed out everywhere: no trusted device left", func(t *testing.T) {
		trust(1)
		status, out := e.call(t, at, http.MethodDelete, userPath+"/sessions", nil)
		require.Equal(t, http.StatusNoContent, status, "%v", out)
		require.Empty(t, devicesOf(t))
	})

	t.Run("another realm's user is not found", func(t *testing.T) {
		status, _ := e.call(t, at, http.MethodDelete, "/api/v1/realms/master/users/"+carol.ID+"/trusted-devices", nil)
		require.Equal(t, http.StatusNotFound, status)
	})
}
