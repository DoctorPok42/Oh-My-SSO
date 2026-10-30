package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

func TestAccountCSRF(t *testing.T) {
	a, b := accountCSRF("session-one"), accountCSRF("session-two")
	require.Equal(t, a, accountCSRF("session-one"), "the same session always gets the same token")
	require.NotEqual(t, a, b, "another session, another token")
	require.NotContains(t, a, "session-one")
	require.Len(t, a, 43, "base64url of 32 bytes, no padding")
}

func TestValidRealmName(t *testing.T) {
	for _, ok := range []string{"acme", "my-realm", "r2", strings.Repeat("a", 63)} {
		require.True(t, validRealmName(ok), ok)
	}
	for _, bad := range []string{"", "a", "Acme", "a.b", "a b", "../x", "é-realm", strings.Repeat("a", 64)} {
		require.False(t, validRealmName(bad), bad)
	}
}

func requestWithRealms(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/r/acme/account", nil)
	if value != "" {
		r.AddCookie(&http.Cookie{Name: realmsCookieName, Value: value})
	}
	return r
}

func TestRealmsCookie(t *testing.T) {
	require.Nil(t, realmsFromRequest(requestWithRealms("")))
	require.Equal(t, []string{"acme", "beta"}, realmsFromRequest(requestWithRealms("acme.Bad.beta.acme..x")),
		"malformed names and duplicates are dropped")

	long := strings.Repeat("realm-a.", 3) + "r1.r2.r3.r4.r5.r6.r7.r8.r9.r10.r11"
	require.Len(t, realmsFromRequest(requestWithRealms(long)), maxRememberedOrg)

	// A sign-in puts its realm first.
	w := httptest.NewRecorder()
	rememberRealm(w, requestWithRealms("beta.acme"), "acme")
	c := w.Result().Cookies()[0]
	require.Equal(t, "acme.beta", c.Value)
	require.Equal(t, "/r", c.Path)
	require.True(t, c.HttpOnly)
	require.True(t, c.Secure)

	// Signing out takes it out; the last one removes the cookie.
	w = httptest.NewRecorder()
	forgetRealm(w, requestWithRealms("acme.beta"), "acme")
	require.Equal(t, "beta", w.Result().Cookies()[0].Value)
	w = httptest.NewRecorder()
	forgetRealm(w, requestWithRealms("acme"), "acme")
	require.Equal(t, -1, w.Result().Cookies()[0].MaxAge)
}

func TestTakeFlash(t *testing.T) {
	a := &acct{realm: &domain.Realm{Name: "acme"}}
	take := func(value, query string) (string, string) {
		r := httptest.NewRequest(http.MethodGet, "/r/acme/account"+query, nil)
		if value != "" {
			r.AddCookie(&http.Cookie{Name: accountFlashCookie, Value: value})
		}
		s := &Server{}
		return s.takeFlash(httptest.NewRecorder(), r, a)
	}
	n, e := take("profile_saved", "")
	require.Equal(t, flashText["profile_saved"], n)
	require.Empty(t, e)

	n, _ = take("sessions_revoked.3", "")
	require.Equal(t, "Your other sessions were signed out (3).", n)

	_, e = take("not_found", "")
	require.Equal(t, flashText["not_found"], e, "shown as an error")

	n, e = take("<script>alert(1)</script>", "")
	require.Empty(t, n+e, "only known keys: the cookie never carries text")

	n, _ = take("", "?done=passkey")
	require.Equal(t, flashText["passkey_added"], n)
}

func TestGroupKey(t *testing.T) {
	require.Equal(t, "JBSW Y3DP EHPK 3PXP", groupKey("JBSWY3DPEHPK3PXP"))
	require.Equal(t, "ABCD E", groupKey("ABCDE"))
	require.Empty(t, groupKey(""))
}

func TestInitialsOf(t *testing.T) {
	require.Equal(t, "DS", initialsOf("Dana Scully"))
	require.Equal(t, "É", initialsOf("élodie"))
	require.Equal(t, "?", initialsOf("  "))
	require.Equal(t, "AB", initialsOf("(Alice) Bob Carol"))
}

func TestSignInMethod(t *testing.T) {
	require.Equal(t, "a passkey", signInMethod(service.AccountSession{AuthMethod: domain.AuthMethodHardwareKey}))
	require.Equal(t, "your password", signInMethod(service.AccountSession{AuthMethod: domain.AuthMethodPassword}))
	require.Equal(t, "your password and an authenticator app", signInMethod(service.AccountSession{
		AuthMethod: domain.AuthMethodPassword, MFAVerified: true, MFAMethod: string(domain.MfaMethodTOTP)}))
	require.Equal(t, "your password on a trusted device", signInMethod(service.AccountSession{
		AuthMethod: domain.AuthMethodPassword, TrustedDevice: true}))
}

// Every action of the activity list has its own sentence: none falls back
// to the generic one.
func TestActivityText_EveryAction(t *testing.T) {
	for _, action := range service.AccountActivityActions {
		text := activityText(service.ActivityEntry{Action: action})
		require.NotEqual(t, "Account updated", text, action)
		require.NotEmpty(t, text, action)
	}
	require.Equal(t, "Access removed for Payroll",
		activityText(service.ActivityEntry{Action: "consent_revoked", Details: map[string]any{"client": "Payroll"}}))
	require.Equal(t, "Added a passkey",
		activityText(service.ActivityEntry{Action: "mfa_method_enrolled", Details: map[string]any{"type": "passkey"}}))
}
