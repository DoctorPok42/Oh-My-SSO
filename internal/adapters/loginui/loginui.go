// Package loginui holds the sign-in pages shared by the protocol adapters:
// OIDC (Step 10) and SAML (Step 11) show the same page.
//
// The page is deliberately small: it only calls the JSON API that already
// exists (/auth/login, /auth/mfa/verify, passkeys, /auth/step-up), then
// reloads itself; the adapter decides everything on reload. No login logic
// lives here, and Step 14 can restyle it without changing any flow.
//
// It also renders the other pages a browser flow needs: a short message
// ("this link has expired"), an auto-submitted form, which is how SAML hands
// an assertion to a service provider (HTTP-POST binding), and the consent
// page (Step 13), a plain HTML form that works without JavaScript.
//
// Like the adapters, this package never talks to storage: it is HTML only.
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
)

//go:embed web/*.html web/*.js web/*.css
var webFS embed.FS

// PageCSP is the Content-Security-Policy of the pages: only our own script
// and style, requests only to ourselves, no framing (clickjacking).
const PageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
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
	ClientName   string
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
	CancelURL   string
	EnrollURL   string // dev pages only
	// ForgotPasswordURL (Step 12): "Forgot password?" link, "" = hidden.
	ForgotPasswordURL string
}

// ForgotPassword is the data of the "forgot password" page (Step 12).
type ForgotPassword struct {
	RealmDisplay string
	Base         string // "/r/<realm>", prefix of the JSON API
	Assets       string
}

// ResetPassword is the data of the "choose a new password" page (Step 12).
type ResetPassword struct {
	RealmDisplay string
	Base         string
	Assets       string
	MinLength    int // the realm's min_password_length, shown and checked in the browser
	MaxLength    int
}

// Consent is the data of the consent page (Step 13): "Allow <app> to access
// your account?". The form posts back to Action with the request id, the
// one-time token, and decision=allow|deny.
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

// RenderConsent writes the consent page (no script: PageCSP allows the form
// to post to this site only).
func (p *Pages) RenderConsent(w http.ResponseWriter, data Consent) {
	p.render(w, http.StatusOK, "consent.html", PageCSP, data)
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

// Asset serves login.js, login.css, autopost.js and password.js. name is the file name
// (the last path segment of the request).
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
