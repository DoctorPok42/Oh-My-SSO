// Package uikit is the OMSSO design system of the pages served by cmd/idp
// (sign-in, consent, password reset, account console): the tokens and
// components of the admin console (admin/src/app/omsso-theme.css and
// admin/src/components/ui), as one plain stylesheet, web/omsso.css, so that
// a button, a field or a card looks the same on both sides.
//
// The fonts are embedded too (IBM Plex Sans and Mono, latin subset, from
// the npm packages @fontsource/ibm-plex-*, SIL Open Font License, see
// web/IBM-Plex-OFL.txt): no request to a font CDN, nothing to allow in the
// CSP but font-src 'self'.
//
// The pages link omsso.css first, then their own stylesheet (login.css,
// account.css) for what is theirs only. The adapters serve these files at
// their assets path: loginui.Asset falls back to Asset here.
package uikit

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
)

//go:embed web/omsso.css web/*.woff2
var webFS embed.FS

// HasAsset reports whether name is one of the design system's files.
func HasAsset(name string) bool {
	switch path.Ext(name) {
	case ".css", ".woff2":
	default:
		return false
	}
	_, err := fs.Stat(webFS, "web/"+path.Base(name))
	return err == nil
}

// Asset serves omsso.css and the fonts. name is the file name (the last
// path segment of the request).
func Asset(w http.ResponseWriter, r *http.Request, name string) {
	var ctype, cache string
	switch path.Ext(name) {
	case ".css":
		ctype, cache = "text/css; charset=utf-8", "public, max-age=300"
	case ".woff2":
		// A font file never changes under the same name.
		ctype, cache = "font/woff2", "public, max-age=604800"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/" + path.Base(name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", cache)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}
