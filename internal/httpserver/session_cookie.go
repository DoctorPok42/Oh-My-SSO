package httpserver

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/ssocookie"
)

// The security cookies of the public server. Over https they are written as
// __Host-<name>-<realm> with Path=/ (see internal/ssocookie, audit B-18); the
// code reads them under these names (realmMiddleware normalizes the request).
const (
	SessionCookieName = ssocookie.Session

	sessionCookieName         = SessionCookieName
	mfaChallengeCookieName    = ssocookie.MFA
	passkeyCeremonyCookieName = ssocookie.Passkey // the token of a sign-in without password

	// DeviceCookieName is the cookie that identifies a browser in a realm (new
	// device alerts, "Pick an account", the lockout of known devices). The
	// adapters read it to list the accounts remembered on the device.
	DeviceCookieName = ssocookie.Device
	deviceCookieName = DeviceCookieName
)

// WithPublicURL sets the public URL of the server. When it is https, the
// security cookies take the __Host- prefix (internal/ssocookie). Without it,
// they keep their names and paths (development over http, tests).
func WithPublicURL(publicURL string) Option {
	return func(s *Server) { s.secureCookies = ssocookie.Secure(publicURL) }
}

// setCookie writes c (base name, path over http) for the realm.
func (s *Server) setCookie(w http.ResponseWriter, c *http.Cookie, realmName string) {
	ssocookie.Set(w, c, realmName, s.secureCookies)
}

func (s *Server) clearCookie(w http.ResponseWriter, name, path, realmName string, sameSite http.SameSite) {
	ssocookie.Clear(w, name, path, realmName, s.secureCookies, sameSite)
}

func sessionCookiePath(realmName string) string {
	return "/r/" + realmName
}

// setSessionCookie writes the cookie of a new session.
//
// A remembered session ("Keep me signed in") gets a persistent cookie that
// expires with the session. Any other session gets a browser-session cookie
// (no Expires, no Max-Age): the browser drops it when it closes, like
// Microsoft Entra ID and Keycloak do without their "stay signed in" option.
// Browsers that restore the previous session on start-up may keep it; the
// server-side idle timeout and lifetime still apply either way.
func (s *Server) setSessionCookie(w http.ResponseWriter, realmName, rawToken string, sess *domain.Session) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawToken,
		Path:     sessionCookiePath(realmName),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if sess.RememberMe {
		maxAge := int(time.Until(sess.ExpiresAt).Seconds())
		if maxAge < 1 {
			maxAge = 1
		}
		c.Expires = sess.ExpiresAt
		c.MaxAge = maxAge
	}
	s.setCookie(w, c, realmName)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, realmName string) {
	s.clearCookie(w, sessionCookieName, sessionCookiePath(realmName), realmName, http.SameSiteLaxMode)
}

func sessionTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func mfaChallengeCookiePath(realmName string) string {
	return "/r/" + realmName + "/auth/mfa"
}

func (s *Server) setMFAChallengeCookie(w http.ResponseWriter, realmName, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	s.setCookie(w, &http.Cookie{
		Name:     mfaChallengeCookieName,
		Value:    rawToken,
		Path:     mfaChallengeCookiePath(realmName),
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		// Strict: the second step always comes from our own login page.
		SameSite: http.SameSiteStrictMode,
	}, realmName)
}

func (s *Server) clearMFAChallengeCookie(w http.ResponseWriter, realmName string) {
	s.clearCookie(w, mfaChallengeCookieName, mfaChallengeCookiePath(realmName), realmName, http.SameSiteStrictMode)
}

func mfaChallengeTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(mfaChallengeCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func passkeyCeremonyCookiePath(realmName string) string {
	return "/r/" + realmName + "/auth/passkey"
}

func (s *Server) setPasskeyCeremonyCookie(w http.ResponseWriter, realmName, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	s.setCookie(w, &http.Cookie{
		Name:     passkeyCeremonyCookieName,
		Value:    rawToken,
		Path:     passkeyCeremonyCookiePath(realmName),
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		// Strict: both calls come from our own sign-in page.
		SameSite: http.SameSiteStrictMode,
	}, realmName)
}

func (s *Server) clearPasskeyCeremonyCookie(w http.ResponseWriter, realmName string) {
	s.clearCookie(w, passkeyCeremonyCookieName, passkeyCeremonyCookiePath(realmName), realmName, http.SameSiteStrictMode)
}

func passkeyCeremonyTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(passkeyCeremonyCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// deviceCookieMaxAge: one year (browsers cap cookie lifetimes at 400 days).
const deviceCookieMaxAge = 365 * 24 * time.Hour

// deviceIDFromRequest returns the id of the device cookie, or "" when
// absent or not in the format we generate (crypto/rand.Text: 26 characters
// of base32), so a crafted cookie cannot inject anything.
func deviceIDFromRequest(r *http.Request) string {
	c, err := r.Cookie(deviceCookieName)
	if err != nil || !service.IsDeviceID(c.Value) {
		return ""
	}
	return c.Value
}

// ensureDeviceCookie returns the device id of the browser, creating it if
// needed, and (re)sets the cookie so its year starts again.
func (s *Server) ensureDeviceCookie(w http.ResponseWriter, r *http.Request, realmName string) string {
	id := deviceIDFromRequest(r)
	if id == "" {
		id = rand.Text()
	}
	s.setDeviceCookie(w, realmName, id)
	return id
}

func (s *Server) setDeviceCookie(w http.ResponseWriter, realmName, id string) {
	s.setCookie(w, &http.Cookie{
		Name:     deviceCookieName,
		Value:    id,
		Path:     sessionCookiePath(realmName),
		MaxAge:   int(deviceCookieMaxAge.Seconds()),
		Expires:  time.Now().Add(deviceCookieMaxAge),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}, realmName)
}

// cookiesOfRealm runs first on every request of a realm (realmMiddleware).
// Over https it puts the realm's __Host- cookies under their base names, for
// the code and the adapters (ssocookie.Normalize). A browser that still has
// the former session or device cookie (before the __Host- prefix) gets the
// new one, and loses the former: one visit moves it over. Short-lived
// cookies (sign-in steps) are only read: they end with their sign-in.
//
// TRANSITION (one version): reading the former cookies goes away with the
// next version; a browser not seen in between signs in again.
func (s *Server) cookiesOfRealm(w http.ResponseWriter, r *http.Request, realm *domain.Realm) {
	former := ssocookie.Former(r, realm.Name, s.secureCookies) // nil over http: nothing to move
	ssocookie.Normalize(r, realm.Name)
	if id, ok := former[deviceCookieName]; ok && service.IsDeviceID(id) {
		s.setDeviceCookie(w, realm.Name, id)
	}
	if raw, ok := former[sessionCookieName]; ok && raw != "" && s.sessions != nil {
		sess, err := s.sessions.Peek(r.Context(), realm.ID, raw)
		if err != nil {
			return // ended or unknown: nothing to move, it stops working anyway
		}
		s.setSessionCookie(w, realm.Name, raw, sess)
		slog.DebugContext(r.Context(), "session cookie moved to its __Host- name", "realm", realm.Name)
	}
}
