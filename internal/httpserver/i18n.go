package httpserver

import (
	"context"
	"net/http"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/i18n"
)

// Languages of the pages (package i18n). Every request of a realm carries
// what is known of its reader's language (i18n.Prefs, set by
// realmMiddleware); the pages pick it when they are rendered:
//
//	the signed-in user's choice   profile "locale" (account console)
//	ui_locales                    OIDC sign-ins (the adapter adds them)
//	this browser's language       the omsso_locale cookie
//	the realm's default           Settings, default_locale
//	English

// WithI18n sets the languages of the pages. Without it, the embedded ones.
func WithI18n(b *i18n.Bundle) Option {
	return func(s *Server) { s.i18n = b }
}

// withLangPrefs puts the language preferences of a request in its context.
// The user and the realm default are looked up only if a page is rendered.
func (s *Server) withLangPrefs(r *http.Request, realm *domain.Realm) context.Context {
	ctx := r.Context()
	return i18n.WithPrefs(ctx, i18n.Prefs{
		Browser: languageCookie(r),
		User:    i18n.Lazy(func() string { return s.sessionUserLocale(ctx, r, realm) }),
		Realm:   i18n.Lazy(func() string { return s.sessions.RealmLocale(ctx, realm.ID) }),
	})
}

// sessionUserLocale: the language chosen by the user of this browser's
// session in the realm ("" without one). The session is only read (Peek):
// rendering a page in the right language must not count as activity.
func (s *Server) sessionUserLocale(ctx context.Context, r *http.Request, realm *domain.Realm) string {
	if s.mfa == nil {
		return ""
	}
	sess, err := s.sessions.Peek(ctx, realm.ID, sessionTokenFromRequest(r))
	if err != nil {
		return ""
	}
	u, err := s.mfa.User(ctx, sess.UserID)
	if err != nil || u.RealmID != realm.ID {
		return ""
	}
	return userLocale(u)
}

// userLocale: the user's language (profile "locale", the OIDC claim), ""
// if they never chose one.
func userLocale(u *domain.User) string {
	l, _ := u.Profile["locale"].(string)
	return l
}

// loc returns the texts of the request's language.
func (s *Server) loc(r *http.Request) *i18n.Localizer { return s.i18n.For(r.Context()) }

// rememberLocale: after a sign-in, this browser's language becomes the
// account's (when it has one), so that the next sign-in page is in it too.
func (s *Server) rememberLocale(w http.ResponseWriter, r *http.Request, u *domain.User) {
	lang := s.i18n.Match(userLocale(u))
	if lang != "" && lang != languageCookie(r) {
		setLanguageCookie(w, lang, true)
	}
}

// languageCookie reads the browser's language ("" if none).
func languageCookie(r *http.Request) string {
	c, err := r.Cookie(i18n.Cookie)
	if err != nil {
		return ""
	}
	return i18n.CleanTag(c.Value)
}

// setLanguageCookie remembers the language of this browser. Not HttpOnly:
// nothing secret, and the admin console reads it the same way. secure: HTTPS.
func setLanguageCookie(w http.ResponseWriter, lang string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: i18n.Cookie, Value: lang, Path: "/", MaxAge: i18n.CookieMaxAge,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}
