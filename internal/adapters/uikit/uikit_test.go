package uikit_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/adapters/uikit"
)

func TestAssets(t *testing.T) {
	for name, ctype := range map[string]string{
		"omsso.css":               "text/css; charset=utf-8",
		"ibm-plex-sans-400.woff2": "font/woff2",
		"ibm-plex-sans-500.woff2": "font/woff2",
		"ibm-plex-sans-600.woff2": "font/woff2",
		"ibm-plex-sans-700.woff2": "font/woff2",
		"ibm-plex-mono-400.woff2": "font/woff2",
	} {
		require.True(t, uikit.HasAsset(name), name)
		w := httptest.NewRecorder()
		uikit.Asset(w, httptest.NewRequest(http.MethodGet, "/x/"+name, nil), name)
		require.Equal(t, http.StatusOK, w.Code, name)
		require.Equal(t, ctype, w.Header().Get("Content-Type"), name)
		require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		require.NotEmpty(t, w.Body.Bytes(), name)
	}
	for _, name := range []string{"IBM-Plex-OFL.txt", "uikit.go", "../uikit.go", "login.css", "x.woff2", ""} {
		require.False(t, uikit.HasAsset(name), name)
	}
}

// Every font the stylesheet names is one of the embedded files.
func TestStylesheetFonts(t *testing.T) {
	w := httptest.NewRecorder()
	uikit.Asset(w, httptest.NewRequest(http.MethodGet, "/x/omsso.css", nil), "omsso.css")
	urls := regexp.MustCompile(`url\(([a-z0-9-]+\.woff2)\)`).FindAllStringSubmatch(w.Body.String(), -1)
	require.Len(t, urls, 5)
	for _, m := range urls {
		require.True(t, uikit.HasAsset(m[1]), m[1])
	}
}
