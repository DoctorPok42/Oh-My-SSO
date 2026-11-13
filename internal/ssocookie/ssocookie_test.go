package ssocookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/ssocookie"
)

func TestSecure(t *testing.T) {
	require.True(t, ssocookie.Secure("https://sso.example.com"))
	require.True(t, ssocookie.Secure(" HTTPS://sso.example.com/ "))
	require.False(t, ssocookie.Secure("http://localhost:8080"))
	require.False(t, ssocookie.Secure(""))
}

func TestName(t *testing.T) {
	require.Equal(t, "__Host-sso_session-acme", ssocookie.Name(ssocookie.Session, "acme", true))
	require.Equal(t, "sso_session", ssocookie.Name(ssocookie.Session, "acme", false))
}

func setCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	return (&http.Response{Header: rec.Header()}).Cookies()
}

func TestSet(t *testing.T) {
	c := &http.Cookie{Name: ssocookie.Session, Value: "tok", Path: "/r/acme", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}

	t.Run("https: __Host-, Path=/, no Domain, the former one removed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ssocookie.Set(rec, c, "acme", true)
		got := setCookies(rec)
		require.Len(t, got, 2)
		require.Equal(t, "sso_session", got[0].Name, "the former cookie first...")
		require.Equal(t, "/r/acme", got[0].Path)
		require.Equal(t, -1, got[0].MaxAge, "... removed")
		require.Equal(t, "__Host-sso_session-acme", got[1].Name)
		require.Equal(t, "tok", got[1].Value)
		require.Equal(t, "/", got[1].Path)
		require.Empty(t, got[1].Domain)
		require.True(t, got[1].Secure)
		require.True(t, got[1].HttpOnly)
		require.Equal(t, http.SameSiteLaxMode, got[1].SameSite)
		require.Equal(t, "/r/acme", c.Path, "the caller's cookie is not changed")
	})

	t.Run("http: as before", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ssocookie.Set(rec, c, "acme", false)
		got := setCookies(rec)
		require.Len(t, got, 1)
		require.Equal(t, "sso_session", got[0].Name)
		require.Equal(t, "/r/acme", got[0].Path)
	})

	t.Run("clear: both names", func(t *testing.T) {
		rec := httptest.NewRecorder()
		ssocookie.Clear(rec, ssocookie.MFA, "/r/acme/auth/mfa", "acme", true, http.SameSiteStrictMode)
		got := setCookies(rec)
		require.Len(t, got, 2)
		for _, c := range got {
			require.Equal(t, -1, c.MaxAge)
		}
		require.Equal(t, "__Host-sso_mfa-acme", got[1].Name)
	})
}

func request(cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/r/acme/account", nil)
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	return r
}

func value(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func TestNormalize(t *testing.T) {
	t.Run("the realm's __Host- cookies under their base names", func(t *testing.T) {
		r := request("__Host-sso_session-acme=new; __Host-sso_device-acme=dev; omsso_locale=fr")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "new", value(r, "sso_session"))
		require.Equal(t, "dev", value(r, "sso_device"))
		require.Equal(t, "fr", value(r, "omsso_locale"), "other cookies kept")
	})

	t.Run("a bare cookie beside a __Host- one is dropped (cookie tossing)", func(t *testing.T) {
		r := request("sso_session=planted; __Host-sso_session-acme=mine")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "mine", value(r, "sso_session"))
		require.Len(t, r.Cookies(), 1)

		r = request("__Host-sso_session-acme=mine; sso_session=planted")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "mine", value(r, "sso_session"), "whatever the order")
	})

	t.Run("former cookies alone are kept (one version of transition)", func(t *testing.T) {
		r := request("sso_session=old; sso_device=olddev")
		require.Equal(t, map[string]string{"sso_session": "old", "sso_device": "olddev"}, ssocookie.Former(r, "acme", true))
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "old", value(r, "sso_session"))
		require.Equal(t, "olddev", value(r, "sso_device"))
	})

	t.Run("another realm's cookie is not this realm's", func(t *testing.T) {
		r := request("__Host-sso_session-other=theirs; __Host-sso_session-acme=mine")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "mine", value(r, "sso_session"))
		require.Equal(t, "theirs", value(r, "__Host-sso_session-other"), "left as it is, read by nobody here")

		r = request("__Host-sso_session-other=theirs")
		ssocookie.Normalize(r, "acme")
		require.Empty(t, value(r, "sso_session"))
		require.Nil(t, ssocookie.Former(r, "acme", true))
	})

	t.Run("http: no former cookie to move, no __Host- one to read", func(t *testing.T) {
		r := request("sso_session=current; sso_device=dev")
		require.Nil(t, ssocookie.Former(r, "acme", false), "over http the base names are the current ones")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "current", value(r, "sso_session"))
		require.Equal(t, "sso_session=current; sso_device=dev", r.Header.Get("Cookie"), "untouched")
	})

	t.Run("an unknown __Host- name is not a security cookie", func(t *testing.T) {
		r := request("__Host-sso_theme-acme=x; sso_session=old")
		ssocookie.Normalize(r, "acme")
		require.Equal(t, "old", value(r, "sso_session"))
		require.Equal(t, "x", value(r, "__Host-sso_theme-acme"))
	})
}
