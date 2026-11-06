package uikit_test

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// A browser with this version gets a 304; one that accepts gzip gets the
// file compressed; the same address must then vary on Accept-Encoding.
func TestStaticFilesCaching(t *testing.T) {
	get := func(h http.Header) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/x/omsso.css", nil)
		for k, v := range h {
			r.Header[k] = v
		}
		w := httptest.NewRecorder()
		uikit.Asset(w, r, "omsso.css")
		return w
	}

	plain := get(nil)
	require.Equal(t, http.StatusOK, plain.Code)
	require.Empty(t, plain.Header().Get("Content-Encoding"))
	require.Equal(t, uikit.StaticCache, plain.Header().Get("Cache-Control"))
	require.Equal(t, "Accept-Encoding", plain.Header().Get("Vary"))
	etag := plain.Header().Get("ETag")
	require.Regexp(t, `^"[0-9a-f]{16}"$`, etag)

	packed := get(http.Header{"Accept-Encoding": {"gzip, br"}})
	require.Equal(t, "gzip", packed.Header().Get("Content-Encoding"))
	require.Less(t, packed.Body.Len(), plain.Body.Len())
	z, err := gzip.NewReader(packed.Body)
	require.NoError(t, err)
	body, err := io.ReadAll(z)
	require.NoError(t, err)
	require.Equal(t, plain.Body.Bytes(), body)

	same := get(http.Header{"If-None-Match": {etag}})
	require.Equal(t, http.StatusNotModified, same.Code)
	require.Empty(t, same.Body.Bytes())

	other := get(http.Header{"If-None-Match": {`"0000000000000000"`}})
	require.Equal(t, http.StatusOK, other.Code)
	require.NotEmpty(t, other.Body.Bytes())
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

// The favicon has one source: web/icon.svg. The admin console (Next.js reads
// admin/src/app/icon.svg) keeps a copy, and no page carries its own.
func TestFaviconHasOneSource(t *testing.T) {
	w := httptest.NewRecorder()
	uikit.Asset(w, httptest.NewRequest(http.MethodGet, "/x/icon.svg", nil), "icon.svg")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "image/svg+xml", w.Header().Get("Content-Type"))
	require.True(t, uikit.HasAsset("icon.svg"))
	own := w.Body.String()
	require.Contains(t, own, "<svg")

	if admin, err := os.ReadFile("../../../admin/src/app/icon.svg"); err == nil {
		require.Equal(t, strings.TrimSpace(strings.ReplaceAll(string(admin), "\r\n", "\n")),
			strings.TrimSpace(strings.ReplaceAll(own, "\r\n", "\n")),
			"admin/src/app/icon.svg must be a copy of internal/adapters/uikit/web/icon.svg")
	}

	pages, err := filepath.Glob("../*/web/*.html")
	require.NoError(t, err)
	checked := 0
	for _, p := range pages {
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		if !strings.Contains(string(raw), "<head>") {
			continue
		}
		checked++
		require.Contains(t, string(raw), `href="{{.Assets}}/icon.svg"`, "%s must link the shared favicon", p)
		require.NotContains(t, string(raw), "data:image/svg+xml", "%s carries its own icon", p)
	}
	require.GreaterOrEqual(t, checked, 8)
}
