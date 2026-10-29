package httpserver

import (
	"crypto/rand"
	"net/http"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

const SessionCookieName = "sso_session"

const sessionCookieName = SessionCookieName

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
func setSessionCookie(w http.ResponseWriter, realmName, rawToken string, sess *domain.Session) {
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
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter, realmName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     sessionCookiePath(realmName),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func sessionTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}


const mfaChallengeCookieName = "sso_mfa"

func mfaChallengeCookiePath(realmName string) string {
	return "/r/" + realmName + "/auth/mfa"
}

func setMFAChallengeCookie(w http.ResponseWriter, realmName, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mfaChallengeCookieName,
		Value:    rawToken,
		Path:     mfaChallengeCookiePath(realmName),
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		// Strict: the second step always comes from our own login page.
		SameSite: http.SameSiteStrictMode,
	})
}

func clearMFAChallengeCookie(w http.ResponseWriter, realmName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaChallengeCookieName,
		Value:    "",
		Path:     mfaChallengeCookiePath(realmName),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func mfaChallengeTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(mfaChallengeCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}


// passkeyCeremonyCookieName holds the token of a sign-in without password
const passkeyCeremonyCookieName = "sso_passkey"

func passkeyCeremonyCookiePath(realmName string) string {
	return "/r/" + realmName + "/auth/passkey"
}

func setPasskeyCeremonyCookie(w http.ResponseWriter, realmName, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     passkeyCeremonyCookieName,
		Value:    rawToken,
		Path:     passkeyCeremonyCookiePath(realmName),
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		// Strict: both calls come from our own sign-in page.
		SameSite: http.SameSiteStrictMode,
	})
}

func clearPasskeyCeremonyCookie(w http.ResponseWriter, realmName string) {
	http.SetCookie(w, &http.Cookie{
		Name:     passkeyCeremonyCookieName,
		Value:    "",
		Path:     passkeyCeremonyCookiePath(realmName),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func passkeyCeremonyTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(passkeyCeremonyCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// DeviceCookieName is the cookie that identifies a browser in a realm (new
// device alerts, "Pick an account"). The adapters read it to list the
// accounts remembered on the device.
const DeviceCookieName = "sso_device"

const deviceCookieName = DeviceCookieName

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
func ensureDeviceCookie(w http.ResponseWriter, r *http.Request, realmName string) string {
	id := deviceIDFromRequest(r)
	if id == "" {
		id = rand.Text()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookieName,
		Value:    id,
		Path:     sessionCookiePath(realmName),
		MaxAge:   int(deviceCookieMaxAge.Seconds()),
		Expires:  time.Now().Add(deviceCookieMaxAge),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return id
}
