package accountui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/adapters/accountui"
)

func layout(active string) accountui.Layout {
	org := accountui.Org{Name: "acme", Display: "Acme", URL: "/r/acme/account", Current: true}
	return accountui.Layout{
		Title: "Test", Org: org, Orgs: []accountui.Org{org, {Name: "beta", Display: "Beta", URL: "/r/beta/account"}},
		User:   accountui.Person{Name: "Dana <b>Scully</b>", Email: "dana@example.test", Initials: "DS"},
		Active: active, Base: "/r/acme/account", Assets: "/r/acme/account/assets", CSRF: "tok-123",
		Notice: "Saved.", MFARequired: true,
	}
}

// Every page renders with typical data, with the security headers, and
// escapes what users typed.
func TestRenderEveryPage(t *testing.T) {
	pages, err := accountui.New(nil)
	require.NoError(t, err)
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	factor := accountui.Factor{ID: "f1", Kind: "totp", KindLabel: "Authenticator app", Name: "Phone <i>", CreatedAt: now, LastUsed: &now}
	cases := map[string]any{
		accountui.PageProfile:      accountui.ProfilePage{Layout: layout("profile"), Username: "dana", Email: "dana@example.test", EmailVerified: true, GivenName: "Dana", Saved: true},
		accountui.PageSecurity:     accountui.SecurityPage{Layout: layout("security"), HasPassword: true, PasskeysEnabled: true, Factors: []accountui.Factor{factor}, BackupRemaining: 9, BackupTotal: 10, TrustedDevices: []accountui.TrustedDevice{{ID: "d1", Device: "Firefox on Linux", Current: true, CreatedAt: now, ExpiresAt: now}, {ID: "d2", Device: "Safari on iOS", CreatedAt: now, ExpiresAt: now}}},
		accountui.PagePassword:     accountui.PasswordPage{Layout: layout("security"), Username: "dana", MinLength: 12, MaxLength: 256, FormError: "Wrong."},
		accountui.PageTOTP:         accountui.TOTPPage{Layout: layout("security"), Step: "scan", MethodID: "m1", QR: "data:image/png;base64,AAAA", Secret: "JBSW Y3DP", ExpiresAt: now},
		accountui.PagePasskey:      accountui.PasskeyPage{Layout: layout("security"), API: "/r/acme"},
		accountui.PageRemoveFactor: accountui.RemoveFactorPage{Layout: layout("security"), Factor: factor, Last: true},
		accountui.PageBackupCodes:  accountui.BackupCodesPage{Layout: layout("security"), Step: "show", Codes: []string{"aaaa-bbbb", "cccc-dddd"}, FirstFactor: true},
		accountui.PageSessions: accountui.SessionsPage{Layout: layout("sessions"), Sessions: []accountui.SessionRow{
			{ID: "s1", Current: true, Device: "Firefox on Linux", Location: "France", Method: "your password", StartedAt: now, LastActiveAt: now},
			{ID: "s2", Device: "Safari on iOS", Location: "Unknown location", Method: "a passkey", Apps: []string{"Payroll"}, StartedAt: now, LastActiveAt: now},
		}},
		accountui.PageApps: accountui.AppsPage{Layout: layout("apps"), Apps: []accountui.AppRow{{ClientRef: "c1", Name: "Payroll", Initial: "P", Host: "payroll.example.test", Consent: true, Access: []string{"Your e-mail address"}, GrantedAt: now, SignedIn: true}}},
		accountui.PageHistory: accountui.HistoryPage{Layout: layout("history"), View: "activity", Page: 2, More: true,
			Activity: []accountui.ActivityRow{{At: now, Text: "Password changed", Device: "Firefox on Linux", IPAddress: "192.0.2.1"}, {At: now, Text: "Second steps reset", ByAdmin: true}}},
	}
	for page, data := range cases {
		t.Run(page, func(t *testing.T) {
			w := httptest.NewRecorder()
			pages.RenderPage(w, http.StatusOK, page, data)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			body := w.Body.String()
			require.Contains(t, body, "<!doctype html>")
			require.Contains(t, body, `name="csrf" value="tok-123"`, "the sign-out form at least")
			require.Contains(t, body, "Dana &lt;b&gt;Scully&lt;/b&gt;", "escaped")
			require.NotContains(t, body, "<b>Scully</b>")
			require.Contains(t, body, `href="/r/beta/account"`, "organization switcher")
			require.Contains(t, body, "requires a second step", "MFARequired banner")
			require.Contains(t, body, "Saved.")
			require.NotContains(t, body, "\u2014", "no em dash in the UI")
			h := w.Header()
			require.Equal(t, accountui.CSP, h.Get("Content-Security-Policy"))
			require.Equal(t, "no-store", h.Get("Cache-Control"))
			require.Equal(t, "DENY", h.Get("X-Frame-Options"))
		})
	}
}

func TestRenderPartial(t *testing.T) {
	pages, err := accountui.New(nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	pages.RenderPartial(w, accountui.PageSessions, "sessions-list", accountui.SessionsPage{Layout: layout("sessions")})
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, strings.HasPrefix(w.Body.String(), `<section class="card" id="sessions">`), w.Body.String())

	w = httptest.NewRecorder()
	pages.RenderPartial(w, accountui.PageSessions, "notice-oob", layout("sessions"))
	require.Contains(t, w.Body.String(), `hx-swap-oob="true"`)

	w = httptest.NewRecorder()
	pages.RenderPartial(w, accountui.PageSessions, "no-such-block", nil)
	require.Equal(t, http.StatusInternalServerError, w.Code, "a template error never sends half a page")
}

func TestAssets(t *testing.T) {
	for _, name := range []string{"account.css", "account.js", "htmx.min.js"} {
		require.True(t, accountui.HasAsset(name), name)
		w := httptest.NewRecorder()
		accountui.Asset(w, httptest.NewRequest(http.MethodGet, "/x/"+name, nil), name)
		require.Equal(t, http.StatusOK, w.Code, name)
		require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	}
	for _, name := range []string{"layout.html", "../accountui.go", "login.js", "x.css"} {
		require.False(t, accountui.HasAsset(name), name)
	}
}
