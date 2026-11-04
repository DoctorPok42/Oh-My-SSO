package i18n

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// Which language a page is in, first match wins (Bundle.Pick):
//
//  1. the signed-in user's choice: their account's language (profile
//     "locale"), chosen in the account console
//  2. what the application asked for this sign-in (OIDC ui_locales)
//  3. this browser's language: the Cookie, set by a choice in the account
//     console or a sign-in with an account that has one
//  4. the realm's default language (admin console, Settings)
//  5. English
//
// The browser's Accept-Language is not used: English, or the language the
// realm chose, is the default.

// Cookie keeps the language of this browser (Path=/: every realm, and the
// admin console when it is served on the same host).
const Cookie = "omsso_locale"

// CookieMaxAge: a year, like the theme.
const CookieMaxAge = 365 * 24 * 60 * 60

// Prefs is what a request knows of its reader's language. User and Realm are
// looked up only when a page is rendered (most requests are JSON or tokens):
// set them with Lazy.
type Prefs struct {
	User    func() string // the signed-in user's choice, "" if none
	Hints   []string      // ui_locales, best first
	Browser string        // the Cookie
	Realm   func() string // the realm's default language
}

// Lazy memoizes a lookup (nil stays nil).
func Lazy(f func() string) func() string {
	if f == nil {
		return nil
	}
	return sync.OnceValue(f)
}

type prefsKey struct{}

// WithPrefs puts the preferences of a request in its context.
func WithPrefs(ctx context.Context, p Prefs) context.Context {
	return context.WithValue(ctx, prefsKey{}, p)
}

// PrefsFrom returns the preferences of a request (zero: English).
func PrefsFrom(ctx context.Context) Prefs {
	p, _ := ctx.Value(prefsKey{}).(Prefs)
	return p
}

// WithUser sets the signed-in user's choice (their profile "locale"), when
// the caller already has the user.
func WithUser(ctx context.Context, locale string) context.Context {
	p := PrefsFrom(ctx)
	p.User = func() string { return locale }
	return WithPrefs(ctx, p)
}

// WithHints sets what the application asked for (OIDC ui_locales: tags
// separated by spaces, best first).
func WithHints(ctx context.Context, uiLocales []string) context.Context {
	p := PrefsFrom(ctx)
	p.Hints = uiLocales
	return WithPrefs(ctx, p)
}

// Pick chooses the language of a request (see the order above).
func (b *Bundle) Pick(p Prefs) string {
	if p.User != nil {
		if l := b.Match(p.User()); l != "" {
			return l
		}
	}
	for _, h := range p.Hints {
		if l := b.Match(h); l != "" {
			return l
		}
	}
	if l := b.Match(p.Browser); l != "" {
		return l
	}
	if p.Realm != nil {
		if l := b.Match(p.Realm()); l != "" {
			return l
		}
	}
	return English
}

// For returns the texts of the request's language.
func (b *Bundle) For(ctx context.Context) *Localizer {
	if b == nil {
		return &Localizer{lang: English}
	}
	return b.Get(b.Pick(PrefsFrom(ctx)))
}

// FromCookie reads the browser's language ("" if none).
func FromCookie(r *http.Request) string {
	c, err := r.Cookie(Cookie)
	if err != nil {
		return ""
	}
	v := Normalize(c.Value)
	if !validTag(v) {
		return ""
	}
	return v
}

// SetCookie remembers the language of this browser. Not HttpOnly: nothing
// secret, and the admin console reads it the same way. secure: HTTPS.
func SetCookie(w http.ResponseWriter, lang string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: Cookie, Value: lang, Path: "/", MaxAge: CookieMaxAge,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// SplitHints turns a ui_locales parameter ("fr-CA fr en") into tags.
func SplitHints(v string) []string { return strings.Fields(v) }
