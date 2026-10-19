package loginui

import (
	"bytes"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newPages(t *testing.T) *Pages {
	t.Helper()
	p, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return p
}

func TestLoginPageRenders(t *testing.T) {
	p := newPages(t)
	w := httptest.NewRecorder()
	p.RenderLogin(w, 200, Login{
		RealmDisplay: "Acme <Corp>", ClientName: `Pay"roll`, ClientID: "payroll", Base: "/r/acme",
		Assets: "/r/acme/oidc/assets", Mode: "stepup", Methods: "totp", CancelURL: "/r/acme/oidc/login?id=x&cancel=1",
	})
	body := w.Body.String()
	require.Contains(t, body, "Acme &lt;Corp&gt;", "html/template escapes")
	require.Contains(t, body, `data-mode="stepup"`)
	require.Contains(t, body, `data-client-param="client_id"`, "OIDC is the default")
	require.Contains(t, body, "Confirm it")
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'self'")
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.False(t, strings.Contains(body, "<script>"), "no inline script: the CSP would block it")

	for _, f := range []string{"login.js", "login.css", "autopost.js"} {
		data, err := webFS.ReadFile("web/" + f)
		require.NoError(t, err)
		require.True(t, bytes.Contains(data, []byte{'\n'}))
	}
}

func TestLoginPageSAMLClientParam(t *testing.T) {
	p := newPages(t)
	w := httptest.NewRecorder()
	p.RenderLogin(w, 200, Login{ClientParam: "entity_id", ClientID: "https://sp.example.test/metadata", Mode: "login"})
	require.Contains(t, w.Body.String(), `data-client-param="entity_id"`)
	require.Contains(t, w.Body.String(), `data-client-id="https://sp.example.test/metadata"`)
}

func TestAutoPost(t *testing.T) {
	p := newPages(t)

	t.Run("hidden fields are escaped, no inline script", func(t *testing.T) {
		w := httptest.NewRecorder()
		require.NoError(t, p.RenderAutoPost(w, AutoPost{
			Action: "https://sp.example.test/acs", Assets: "/r/acme/saml/assets", Title: "Signing you in",
			Fields: []Field{{"SAMLResponse", `PD94bW"><script>`}, {"RelayState", "a&b"}},
		}))
		body := w.Body.String()
		require.Contains(t, body, `action="https://sp.example.test/acs"`)
		require.Contains(t, body, `name="SAMLResponse" value="PD94bW&#34;&gt;&lt;script&gt;"`)
		require.Contains(t, body, `value="a&amp;b"`)
		require.NotContains(t, body, "<script>")
		csp := w.Header().Get("Content-Security-Policy")
		require.Contains(t, csp, "script-src 'self'")
		require.NotContains(t, csp, "form-action", "the form leaves for the service provider")
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})

	t.Run("only http(s) actions", func(t *testing.T) {
		for _, bad := range []string{"javascript:alert(1)", "data:text/html,x", "/relative", ""} {
			require.Error(t, p.RenderAutoPost(httptest.NewRecorder(), AutoPost{Action: bad}), bad)
		}
	})
}
