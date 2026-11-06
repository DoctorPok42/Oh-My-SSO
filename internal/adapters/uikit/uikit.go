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
//
// web/icon.svg is the favicon of every page of the IdP: change it there, once.
// It is a copy of admin/src/app/icon.svg (Next.js reads it from there for the
// admin console); a test keeps the two equal.
package uikit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
)

//go:embed web/omsso.css web/icon.svg web/*.woff2
var webFS embed.FS

// HasAsset reports whether name is one of the design system's files.
func HasAsset(name string) bool {
	switch path.Ext(name) {
	case ".css", ".woff2", ".svg":
	default:
		return false
	}
	_, err := fs.Stat(webFS, "web/"+path.Base(name))
	return err == nil
}

// Asset serves omsso.css, icon.svg (the favicon of every page) and the fonts. name is the file name (the last
// path segment of the request).
func Asset(w http.ResponseWriter, r *http.Request, name string) {
	var ctype, cache string
	switch path.Ext(name) {
	case ".css":
		ctype, cache = "text/css; charset=utf-8", StaticCache
	case ".svg":
		ctype, cache = "image/svg+xml", StaticCache
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
	Serve(w, r, "uikit/"+path.Base(name), data, ctype, cache)
}

// StaticCache: the stylesheets and scripts of the pages. Fresh for 5 minutes;
// after that the browser uses its copy at once and checks it in the
// background: a page never waits for them, and a new version (a new ETag)
// shows on the next page.
const StaticCache = "public, max-age=300, stale-while-revalidate=604800"

// staticFile: one embedded file, ready to serve: they never change while the
// process runs, so it is hashed and compressed once.
type staticFile struct {
	etag string
	gz   []byte // nil: not worth compressing (fonts already are)
}

var staticFiles sync.Map // key -> *staticFile

// Serve answers with an embedded file: 304 when the browser has this version
// (the ETag is a hash of the content), gzip when it accepts it. key names the
// file among all those served here.
func Serve(w http.ResponseWriter, r *http.Request, key string, data []byte, ctype, cache string) {
	v, ok := staticFiles.Load(key)
	if !ok {
		v, _ = staticFiles.LoadOrStore(key, newStaticFile(data, ctype))
	}
	f := v.(*staticFile)
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", cache)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", f.etag)
	if f.gz != nil {
		h.Set("Vary", "Accept-Encoding")
	}
	if strings.Contains(r.Header.Get("If-None-Match"), f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if f.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		data = f.gz
	}
	_, _ = w.Write(data)
}

func newStaticFile(data []byte, ctype string) *staticFile {
	sum := sha256.Sum256(data)
	f := &staticFile{etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	if !strings.HasPrefix(ctype, "text/") {
		return f
	}
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression) // a valid level: no error
	if _, err := z.Write(data); err == nil && z.Close() == nil {
		f.gz = b.Bytes()
	}
	return f
}
