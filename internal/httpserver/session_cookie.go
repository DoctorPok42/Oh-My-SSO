package httpserver

import (
	"crypto/rand"
	"net/http"
	"time"
)

// SessionCookieName is the SSO session cookie. Exported for the protocol
// adapters (Step 10), which read it on their login pages.
const SessionCookieName = "sso_session"

const sessionCookieName = SessionCookieName

func sessionCookiePath(realmName string) string {
	return "/r/" + realmName
}

func setSessionCookie(w http.ResponseWriter, realmName, rawToken string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawToken,
		Path:     sessionCookiePath(realmName),
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
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

// --- MFA login challenge cookie (Step 9) --------------------------------------

// mfaChallengeCookieName holds the random token linking "password OK" to
// "second factor OK". It only exists between the two steps (5 minutes max)
// and is only sent to /r/{realm}/auth/mfa/... (Path).
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

// --- device cookie (Step 12) --------------------------------------------------

// deviceCookieName holds a random id that stays in the browser for a year.
// Sessions store its hash (Session.device_fingerprint): a sign-in whose id
// was never seen on the account comes from a new device. It grants nothing
// by itself, it is only a "have we seen this browser before?" marker.
const deviceCookieName = "sso_device"

// deviceCookieMaxAge: one year (browsers cap cookie lifetimes at 400 days).
const deviceCookieMaxAge = 365 * 24 * time.Hour

// deviceIDFromRequest returns the id of the device cookie, or "" when
// absent or not in the format we generate (crypto/rand.Text: 26 characters
// of base32), so a crafted cookie cannot inject anything.
func deviceIDFromRequest(r *http.Request) string {
	c, err := r.Cookie(deviceCookieName)
	if err != nil || len(c.Value) != 26 {
		return ""
	}
	for _, ch := range c.Value {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= '2' && ch <= '7') {
			return ""
		}
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
