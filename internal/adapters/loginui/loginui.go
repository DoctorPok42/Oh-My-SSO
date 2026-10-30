package loginui

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"sso.internal/sso/internal/adapters/uikit"
	"sso.internal/sso/internal/core"
)

//go:embed web/*.html web/*.js web/*.css
var webFS embed.FS

// PageCSP is the Content-Security-Policy of the pages: only our own script,
// style and fonts (the design system's, see uikit), requests only to
// ourselves, no framing (clickjacking).
const PageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Pages renders the templates.
type Pages struct {
	t      *template.Template
	logger *slog.Logger
}

// New parses the embedded templates. logger may be nil (slog.Default()).
func New(logger *slog.Logger) (*Pages, error) {
	t, err := template.ParseFS(webFS, "web/*.html")
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Pages{t: t, logger: logger}, nil
}

// Login is the data of the sign-in page.
type Login struct {
	RealmDisplay string
	// ClientName: "to continue to <ClientName>". Empty (the account
	// console): Subtitle instead, if any.
	ClientName string
	Subtitle   string
	// Notice: one sentence above the form ("For your security, ...").
	Notice string
	// ClientParam and ClientID tell the page how to name the application to
	// the JSON API, so that its MFA policy applies right away: "client_id"
	// (OIDC) or "entity_id" (SAML), and its value.
	ClientParam string
	ClientID    string
	Base        string // "/r/<realm>", prefix of the JSON API
	Assets      string // where Asset is mounted, e.g. "/r/<realm>/oidc/assets"
	Mode        string // login | stepup | enroll
	Methods     string // stepup: allowed methods, comma separated ("" = any)
	Passkeys    bool
	LoginHint   string
	// CancelURL: the link at the bottom ("" = no link), with CancelText
	// ("" = "Cancel and go back to the application").
	CancelURL  string
	CancelText string
	// EnrollURL: where to add a second factor when the application requires
	// one the user does not have (the Security page of the account console).
	EnrollURL         string
	ForgotPasswordURL string
	// RememberMe shows "Keep me signed in" under the password, for at
	// most RememberMeDays days.
	RememberMe     bool
	RememberMeDays int

	// "Pick an account" (Mode "pick"): the accounts of this device, the
	// signed-in one first.
	Accounts []Account
	// ContinueURL and ContinueToken let the signed-in tile go on with its
	// session (OIDC prompt=select_account). Empty when no tile is signed in.
	ContinueURL   string
	ContinueToken string
	RequestID     string
}

// Account is one tile of "Pick an account".
type Account struct {
	ID         string // "": not remembered, no "Forget" button
	Name       string
	Label      string // second line: e-mail, else username
	Identifier string // pre-fills the username field
	Initials   string
	SignedIn   bool
	// Methods: the sign-in methods of the account, best first, comma
	// separated ("passkey,password"). A click on the tile starts the first.
	Methods string
}

// AccountsFrom turns the core's accounts into tiles.
func AccountsFrom(in []core.Account) []Account {
	out := make([]Account, 0, len(in))
	for _, a := range in {
		label := a.Email
		if label == "" || label == a.Name {
			label = a.Username
		}
		if label == a.Name {
			label = ""
		}
		methods := make([]string, 0, len(a.Methods))
		for _, m := range a.Methods {
			methods = append(methods, string(m))
		}
		out = append(out, Account{
			ID: a.ID, Name: a.Name, Label: label, Identifier: a.Identifier,
			Initials: initials(a.Name), SignedIn: a.SignedIn,
			Methods: strings.Join(methods, ","),
		})
	}
	return out
}

// initials: first letter of the first two words ("Alice Martin" -> "AM").
func initials(name string) string {
	var out []rune
	for _, w := range strings.Fields(name) {
		for _, r := range w {
			out = append(out, unicode.ToUpper(r))
			break
		}
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// LogoutConfirm is the "Sign out of <realm>?" page: an application asked to
// end a session that is not the one of this browser (OIDC RP-Initiated
// Logout 1.0, section 2: the OP must ask in that case).
type LogoutConfirm struct {
	RealmDisplay string
	ClientName   string
	Account      string // e-mail or username of the session's account
	Action       string // form action
	RequestID    string
	Token        string // one-time anti-CSRF token
	Assets       string
}

type ForgotPassword struct {
	RealmDisplay string
	Base         string // "/r/<realm>", prefix of the JSON API
	Assets       string
}

type ResetPassword struct {
	RealmDisplay string
	Base         string
	Assets       string
	MinLength    int // the realm's min_password_length, shown and checked in the browser
	MaxLength    int
}

type Consent struct {
	RealmDisplay string
	ClientName   string
	// ClientHost is where the browser goes after the answer (host of the
	// redirect URI or ACS URL): a user can spot a look-alike application.
	ClientHost string
	Username   string // who is signed in
	Items      []ConsentLine
	// MoreThanBefore: the user approved this application before and it now
	// asks for more (the new lines are marked).
	MoreThanBefore bool
	Action         string // form action, e.g. "/r/<realm>/oidc/consent"
	RequestID      string
	Token          string // one-time anti-CSRF token, checked by the adapter
	Assets         string
}

// ConsentLine is one item of the consent page.
type ConsentLine struct {
	Title       string
	Description string
	New         bool // not approved before
}

// Message is a short page with a title and one sentence.
type Message struct {
	Title string
	Text  string
}

// AutoPost is a form that the browser submits by itself to Action (SAML
// HTTP-POST binding). Fields are hidden inputs.
type AutoPost struct {
	Action string
	Fields []Field
	Assets string
	// Title and Text are shown while the form submits (and stay visible
	// without JavaScript, next to a "Continue" button).
	Title string
	Text  string
}

// Field is one hidden input of an AutoPost form.
type Field struct {
	Name  string
	Value string
}

// RememberMeOffer turns the session options of a realm into the two
// remember-me fields of Login: show "Keep me signed in", for how many days.
func RememberMeOffer(o core.SessionOptions) (show bool, days int) {
	days = int(o.RememberMeMaxAge / (24 * time.Hour))
	return o.RememberMe && days > 0, days
}

// RenderLogin writes the sign-in page.
func (p *Pages) RenderLogin(w http.ResponseWriter, status int, data Login) {
	if data.ClientParam == "" {
		data.ClientParam = "client_id"
	}
	p.render(w, status, "login.html", PageCSP, data)
}

// RenderForgotPassword writes the "forgot password" page.
func (p *Pages) RenderForgotPassword(w http.ResponseWriter, data ForgotPassword) {
	p.render(w, http.StatusOK, "forgot.html", PageCSP, data)
}

// RenderResetPassword writes the "choose a new password" page. The token is
// not in the data: it stays in the URL fragment (#token=...), which the
// browser never sends to the server; password.js reads it.
func (p *Pages) RenderResetPassword(w http.ResponseWriter, data ResetPassword) {
	p.render(w, http.StatusOK, "reset.html", PageCSP, data)
}

// RenderConsent writes the consent page (no script). After the answer the
// browser is redirected to the application (OIDC: its redirect_uri, another
// site). Browsers apply form-action to the redirects that follow a form
// submission, so PageCSP's form-action 'self' blocked "Allow" and "Deny" in
// Chromium: the page uses redirectCSP. The form itself has a fixed action
// on this server.
func (p *Pages) RenderConsent(w http.ResponseWriter, data Consent) {
	p.render(w, http.StatusOK, "consent.html", redirectCSP, data)
}

// RenderLogoutConfirm writes the sign-out confirmation page. After the
// answer the browser leaves for the application (its registered
// post_logout_redirect_uri): like the auto-post form, the page has no
// form-action rule, which browsers also apply to the redirects that follow
// a submission. The form itself only posts to this server (fixed action).
func (p *Pages) RenderLogoutConfirm(w http.ResponseWriter, data LogoutConfirm) {
	p.render(w, http.StatusOK, "logout.html", redirectCSP, data)
}

// RenderMessage writes a message page. assets: where Asset is mounted.
func (p *Pages) RenderMessage(w http.ResponseWriter, status int, m Message, assets string) {
	p.render(w, status, "message.html", PageCSP, struct {
		Message
		Assets string
	}{m, assets})
}

// autoPostCSP is PageCSP without its form-action rule. The form must leave
// for another site, and browsers also apply form-action to the redirects
// that follow a submission: a service provider whose ACS redirects to
// another host would be blocked. The action itself is checked by the caller
// (a registered ACS URL) and escaped by html/template.
var autoPostCSP = strings.Replace(PageCSP, " form-action 'self';", "", 1)

// redirectCSP: the same rule for our own forms whose answer redirects to an
// application (consent, sign-out confirmation).
var redirectCSP = autoPostCSP

// RenderAutoPost writes a self-submitting form to f.Action, which must be an
// absolute http(s) URL.
func (p *Pages) RenderAutoPost(w http.ResponseWriter, f AutoPost) error {
	u, err := url.Parse(f.Action)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("loginui: auto-post action %q is not an http(s) URL", f.Action)
	}
	p.render(w, http.StatusOK, "autopost.html", autoPostCSP, f)
	return nil
}

func (p *Pages) render(w http.ResponseWriter, status int, name, csp string, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := p.t.ExecuteTemplate(w, name, data); err != nil {
		p.logger.Error("loginui: render page", "page", name, "error", err)
	}
}

// Asset serves login.js, login.css, autopost.js and password.js, and the
// design system's files (uikit: omsso.css and its fonts). name is the file
// name (the last path segment of the request).
func Asset(w http.ResponseWriter, r *http.Request, name string) {
	if uikit.HasAsset(name) {
		uikit.Asset(w, r, name)
		return
	}
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
