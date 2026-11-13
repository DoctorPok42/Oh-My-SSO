// Package ssocookie names the security cookies of the public server (session,
// sign-in steps, device, binding of a sign-in to its browser) and writes them.
//
// Over https (the public URL), a cookie is named __Host-<base>-<realm>, with
// Path=/ and no Domain: only this host can set it, so a neighbouring
// subdomain cannot plant a session or a device of its choice ("cookie
// tossing", audit B-18). __Secure- would not be enough: any https subdomain
// may set such a cookie for the parent domain. __Host- requires Path=/,
// hence the realm in the name: each realm keeps its own cookies, as the
// former Path=/r/<realm> did.
//
// Over http (development), names and paths stay the former ones (base name,
// path under /r/<realm>): browsers refuse __Host- cookies from an insecure
// origin.
//
// The code reads every cookie under its base name: Normalize, run on each
// request of a realm (over http too), puts the realm's __Host- cookies there. During one
// version it also keeps a former cookie (base name) when its __Host- one is
// missing, so that the upgrade signs nobody out; writing a cookie removes the
// former one.
package ssocookie

import (
	"net/http"
	"strings"
)

// The base names of the security cookies.
const (
	Session     = "sso_session"      // SSO session (httpserver)
	MFA         = "sso_mfa"          // second step of a sign-in (httpserver)
	Passkey     = "sso_passkey"      // sign-in without password (httpserver)
	Device      = "sso_device"       // the browser, for a year (httpserver)
	OIDCBrowser = "sso_oidc_browser" // binds an OIDC sign-in to its browser (adapters/oidc)
	SAMLBrowser = "sso_saml_browser" // binds a SAML sign-in to its browser (adapters/saml)
)

// bases: the cookies Normalize reads under their base name.
var bases = []string{Session, MFA, Passkey, Device, OIDCBrowser, SAMLBrowser}

const hostPrefix = "__Host-"

// Secure tells whether the server's cookies take the __Host- prefix: its
// public URL is https.
func Secure(publicURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(publicURL)), "https://")
}

// Name is the name of the cookie base of realm.
func Name(base, realm string, secure bool) string {
	if !secure {
		return base
	}
	return hostPrefix + base + "-" + realm
}

// Set writes c for realm. c.Name is the base name and c.Path the path of the
// cookie over http (under /r/<realm>). Over https it is written under its
// __Host- name with Path=/ and Secure, and the former cookie (base name,
// c.Path) is removed.
func Set(w http.ResponseWriter, c *http.Cookie, realm string, secure bool) {
	out := *c
	if secure {
		out.Name = Name(c.Name, realm, true)
		out.Path = "/"
		out.Domain = ""
		out.Secure = true
		removeFormer(w, c)
	}
	http.SetCookie(w, &out)
}

// Clear removes the cookie base of realm (path: as for Set), under both
// names over https.
func Clear(w http.ResponseWriter, base, path, realm string, secure bool, sameSite http.SameSite) {
	Set(w, &http.Cookie{
		Name: base, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: sameSite,
	}, realm, secure)
}

// removeFormer removes the cookie c was before __Host- (same name and path).
func removeFormer(w http.ResponseWriter, c *http.Cookie) {
	http.SetCookie(w, &http.Cookie{
		Name: c.Name, Value: "", Path: c.Path, MaxAge: -1,
		HttpOnly: c.HttpOnly, Secure: true, SameSite: c.SameSite,
	})
}

// Former tells which security cookies of r are former ones (base name, no
// __Host- one of realm beside them), by base name. Read it before Normalize.
func Former(r *http.Request, realm string, secure bool) map[string]string {
	if !secure {
		return nil
	}
	var out map[string]string
	for _, base := range bases {
		if _, err := r.Cookie(Name(base, realm, true)); err == nil {
			continue
		}
		if c, err := r.Cookie(base); err == nil {
			if out == nil {
				out = map[string]string{}
			}
			out[base] = c.Value
		}
	}
	return out
}

// Normalize rewrites the Cookie header of r so that the code finds the
// security cookies of realm under their base names: the __Host- cookie when
// there is one (a cookie under the base name beside it is dropped: anybody
// on a neighbouring subdomain may have set it), the former cookie otherwise
// (one version of transition). Other cookies are kept as they are.
//
// It does not depend on the server's URL: only this host, over https, can
// set a __Host- cookie, so reading one is always safe, and a part of the
// server that writes them (an adapter) is always understood by the others.
func Normalize(r *http.Request, realm string) {
	if r.Header.Get("Cookie") == "" {
		return
	}
	cookies := r.Cookies()
	hosted := map[string]bool{}
	for _, c := range cookies {
		if base, ok := baseOf(c.Name, realm); ok {
			hosted[base] = true
		}
	}
	if len(hosted) == 0 {
		return // only former cookies, or none: already under their base names
	}
	kept := make([]string, 0, len(cookies))
	seen := map[string]bool{}
	for _, c := range cookies {
		name := c.Name
		if base, ok := baseOf(name, realm); ok {
			if seen[base] {
				continue // the first one, as r.Cookie would read it
			}
			seen[base] = true
			name = base
		} else if hosted[name] {
			continue // a cookie under the base name beside a __Host- one
		}
		kept = append(kept, (&http.Cookie{Name: name, Value: c.Value}).String())
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

// baseOf: the base name of the __Host- cookie name of realm.
func baseOf(name, realm string) (string, bool) {
	rest, ok := strings.CutPrefix(name, hostPrefix)
	if !ok {
		return "", false
	}
	base, ok := strings.CutSuffix(rest, "-"+realm)
	if !ok {
		return "", false
	}
	for _, b := range bases {
		if b == base {
			return base, true
		}
	}
	return "", false
}
