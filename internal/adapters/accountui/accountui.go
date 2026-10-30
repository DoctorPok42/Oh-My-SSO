// Package accountui renders the account console (Step 14c,
// spec-panel-user.md): the pages where a user manages their own account,
// served by cmd/idp at /r/<realm>/account.
//
// Server-rendered HTML (html/template) with htmx for the small actions
// (sign out a session, remove an application...): every form also works
// without JavaScript (a normal POST, then the page again). Only passkeys
// need JavaScript, because the browser's WebAuthn API is JavaScript.
//
// htmx (https://htmx.org, 0BSD licence) is embedded, version 2.0.11
// (web/htmx.min.js, from the npm package htmx.org): no CDN, so the pages
// keep a strict Content-Security-Policy (script-src 'self'). Its settings
// are in the <meta name="htmx-config"> of layout.html.
//
// This package only knows about views: the HTTP layer
// (internal/httpserver/account_*.go) fills them.
package accountui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed web/*.html web/*.css web/*.js
var webFS embed.FS

// CSP of the account pages: our own scripts, styles and fonts only (the
// design system's, package uikit), images from ourselves or data: URIs (the
// QR code of an authenticator app), requests to ourselves only, never in a
// frame.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Page names (one template file each, rendered inside layout.html).
const (
	PageProfile       = "profile"
	PageSecurity      = "security"
	PagePassword      = "password"
	PageTOTP          = "totp"
	PagePasskey       = "passkey"
	PageRemoveFactor  = "remove"
	PageBackupCodes   = "backup-codes"
	PageSessions      = "sessions"
	PageApps          = "apps"
	PageHistory       = "history"
	pageLayout        = "layout.html"
	pageSharedPartial = "shared.html"
)

var pageNames = []string{
	PageProfile, PageSecurity, PagePassword, PageTOTP, PagePasskey, PageRemoveFactor,
	PageBackupCodes, PageSessions, PageApps, PageHistory,
}

// Pages renders the templates.
type Pages struct {
	t      map[string]*template.Template
	logger *slog.Logger
}

var funcs = template.FuncMap{
	// iso: the machine-readable time of a <time datetime="...">.
	"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	// when: the same time for a person, in UTC; account.js shows it in the
	// reader's time zone.
	"when": func(t time.Time) string { return t.UTC().Format("Jan 2, 2006, 15:04 UTC") },
	// day: a date without the time.
	"day":  func(t time.Time) string { return t.UTC().Format("Jan 2, 2006") },
	"add1": func(n int) int { return n + 1 },
	"sub1": func(n int) int { return n - 1 },
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
}

// New parses the embedded templates. logger may be nil (slog.Default()).
func New(logger *slog.Logger) (*Pages, error) {
	if logger == nil {
		logger = slog.Default()
	}
	p := &Pages{t: map[string]*template.Template{}, logger: logger}
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(webFS, "web/"+pageLayout, "web/"+pageSharedPartial, "web/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("accountui: %s: %w", name, err)
		}
		p.t[name] = t
	}
	return p, nil
}

// Org is an organization (realm) of the switcher.
type Org struct {
	Name    string // realm name, part of the URL
	Display string
	URL     string // its account console
	Current bool
}

// Person: the signed-in user, as the header shows them.
type Person struct {
	Name     string
	Email    string
	Initials string
}

// Layout is what every page shows. Every page's data embeds it.
type Layout struct {
	Title string
	Org   Org
	// Orgs: the organizations this browser signed in to, the current one
	// included. One entry: no switcher.
	Orgs []Org
	User Person
	// Active: the tab of the menu (profile, security, sessions, apps,
	// history).
	Active string
	Base   string // "/r/<realm>/account"
	Assets string // Base + "/assets"
	CSRF   string // the anti-CSRF token of every form
	Notice string // a confirmation ("Your password was changed.")
	Error  string // a failure that is not about one field
	// MFARequired: the organization requires a second step the user does
	// not have yet.
	MFARequired bool
	// Theme: the user's choice, "light", "dark" or "system" (ThemeFrom).
	Theme string
}

// ThemeCookie keeps the theme chosen in the console (account.js writes
// it), the same cookie as the admin console's (admin/src/lib/theme.ts).
const ThemeCookie = "omsso_theme"

// ThemeFrom reads the theme of the request: "light", "dark", else "system"
// (follow the device). Read by the server so that the page comes with the
// right class on <html>, without a flash of the other theme.
func ThemeFrom(r *http.Request) string {
	if c, err := r.Cookie(ThemeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return "system"
}

// ThemeClass is the class of <html>: none for "system" (omsso.css then
// follows prefers-color-scheme).
func (l Layout) ThemeClass() string {
	if l.Theme == "light" || l.Theme == "dark" {
		return l.Theme
	}
	return ""
}

type ProfilePage struct {
	Layout
	Username      string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	FormError     string
	Saved         bool
}

// Factor is a second step of sign-in (authenticator app, passkey...).
type Factor struct {
	ID        string
	Kind      string // totp, passkey, security_key: the icon
	KindLabel string // "Authenticator app", "Passkey", "Security key"
	Name      string
	CreatedAt time.Time
	LastUsed  *time.Time
}

// TrustedDevice: a device that skips the second step.
type TrustedDevice struct {
	ID        string
	Device    string // "Firefox on Windows"
	Current   bool   // this browser
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  *time.Time
}

type SecurityPage struct {
	Layout
	HasPassword     bool
	Factors         []Factor
	PasskeysEnabled bool
	BackupRemaining int
	BackupTotal     int
	TrustedDevices  []TrustedDevice
}

type PasswordPage struct {
	Layout
	Username  string // for password managers (hidden field)
	MinLength int
	MaxLength int
	FormError string
}

// TOTPPage is "Add an authenticator app": Step "name", then "scan".
type TOTPPage struct {
	Layout
	Step      string
	Name      string
	MethodID  string
	QR        template.URL // data:image/png;base64,...: made by the server, not user input
	Secret    string       // the key in groups of 4, to type by hand
	ExpiresAt time.Time
	FormError string
}

type PasskeyPage struct {
	Layout
	// API: prefix of the JSON API of the realm ("/r/<realm>").
	API string
}

type RemoveFactorPage struct {
	Layout
	Factor Factor
	// Last: it is the last second step: the backup codes go with it.
	Last      bool
	FormError string
}

// BackupCodesPage: Step "confirm" (the old codes will stop working), then
// "show" (the new codes, shown once).
type BackupCodesPage struct {
	Layout
	Step  string
	Codes []string
	// FirstFactor: the codes come with the first second step just added.
	FirstFactor bool
	FormError   string
}

// SessionRow is one session of the "Sessions" page.
type SessionRow struct {
	ID           string
	Current      bool
	Device       string // "Firefox on Windows"
	Location     string // country, else "Unknown location"
	IPAddress    string
	Method       string // after "Signed in with": "your password", "a passkey"...
	RememberMe   bool
	Apps         []string
	StartedAt    time.Time
	LastActiveAt time.Time
}

type SessionsPage struct {
	Layout
	Sessions []SessionRow
}

// AppRow is one application of the "Connected apps" page.
type AppRow struct {
	ClientRef string
	Name      string
	Initial   string // first letter of the name, for the badge
	Host      string
	Consent   bool
	Access    []string // what it may read, in plain words
	GrantedAt time.Time
	SignedIn  bool
}

type AppsPage struct {
	Layout
	Apps []AppRow
}

// SignInRow is one sign-in attempt of the "History" page.
type SignInRow struct {
	At        time.Time
	Success   bool
	Result    string // "Signed in", "Wrong password"...
	Device    string
	Location  string
	IPAddress string
}

// ActivityRow is one entry of "Account activity".
type ActivityRow struct {
	At        time.Time
	Text      string // "You added an authenticator app (Phone)"
	ByAdmin   bool
	Failed    bool
	Device    string
	IPAddress string
}

type HistoryPage struct {
	Layout
	View     string // signins | activity
	SignIns  []SignInRow
	Activity []ActivityRow
	Page     int // 1-based
	More     bool
}

// RenderPage writes a whole page.
func (p *Pages) RenderPage(w http.ResponseWriter, status int, page string, data any) {
	p.execute(w, status, page, "layout", data)
}

// RenderPartial writes one block of a page (a "define" of its template),
// the answer to an htmx request.
func (p *Pages) RenderPartial(w http.ResponseWriter, page, block string, data any) {
	p.execute(w, http.StatusOK, page, block, data)
}

func (p *Pages) execute(w http.ResponseWriter, status int, page, block string, data any) {
	t, ok := p.t[page]
	if !ok {
		p.logger.Error("accountui: unknown page", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Render first: a template error must not leave half a page.
	var b strings.Builder
	if err := t.ExecuteTemplate(&b, block, data); err != nil {
		p.logger.Error("accountui: render", "page", page, "block", block, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	SecurityHeaders(w.Header())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

// SecurityHeaders: the headers of every account page and fragment.
func SecurityHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// HasAsset reports whether name is one of this package's static files.
func HasAsset(name string) bool {
	switch path.Ext(name) {
	case ".css", ".js":
	default:
		return false
	}
	_, err := fs.Stat(webFS, "web/"+path.Base(name))
	return err == nil
}

// Asset serves account.css, account.js and htmx.min.js.
func Asset(w http.ResponseWriter, r *http.Request, name string) {
	var ctype string
	switch path.Ext(name) {
	case ".js":
		ctype = "text/javascript; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
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
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}
