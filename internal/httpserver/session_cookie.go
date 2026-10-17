package httpserver

import (
	"net/http"
	"time"
)

const sessionCookieName = "sso_session"

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
