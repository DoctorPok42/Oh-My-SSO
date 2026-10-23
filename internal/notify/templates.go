package notify

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
)

// The templates are compiled into the binary (go:embed): nothing to deploy
// next to it, and a typo in a template fails at start-up (LoadTemplates),
// not when the first user forgets their password.
//
// Each e-mail is one file, templates/<name>.tmpl, with three blocks:
//
//	{{define "subject"}}  the subject line (text)
//	{{define "text"}}     the text/plain version
//	{{define "html"}}     the inside of the HTML version
//
// layout.txt.tmpl and layout.html.tmpl wrap them (footer, card). The HTML is
// rendered with html/template, which escapes every value: a username like
// "<script>" ends up as text, never as markup.
//
// https://pkg.go.dev/embed  https://pkg.go.dev/text/template  https://pkg.go.dev/html/template

//go:embed templates/*.tmpl
var templateFS embed.FS

// Data is what the templates can show. The dispatcher fills the fields that
// make sense for the e-mail; the others stay empty and are not shown.
type Data struct {
	Product  string // "Oh-My-SSO"
	Realm    string // realm display name
	Username string

	// Where and when the action happened.
	When      string // "Mon 19 Oct 2026, 20:52 UTC"
	IPAddress string
	Device    string // "Firefox on Windows"
	Location  string // "France"

	// Links.
	ResetURL          string // password_reset
	ExpiresIn         string // password_reset: "30 minutes"
	ForgotPasswordURL string // "change my password" buttons

	// MFA changes.
	MethodLabel string // "authenticator app"
	MethodName  string // label chosen by the user

	// account_locked.
	LockedUntil    string
	LockDuration   string
	FailedAttempts int

	// suspicious_login: plain-language reasons.
	Reasons []string

	// app_connected (Step 13): the application, what it can now receive (as
	// worded on the consent screen), and whether it had access before.
	AppName        string
	AppAccess      []string
	AppAccessAdded bool

	// admin_recovery (Step 14).
	RecoveryKind    string
	RecoveryActor   string
	RecoveryAccount string
}

type htmlData struct {
	Data
	Subject string
}

type buttonData struct{ URL, Label string }

var funcs = map[string]any{
	"button": func(url, label string) buttonData { return buttonData{URL: url, Label: label} },
}

// Templates holds every e-mail, parsed once.
type Templates struct {
	text map[Template]*texttemplate.Template
	html map[Template]*htmltemplate.Template
}

// LoadTemplates parses the embedded templates.
func LoadTemplates() (*Templates, error) {
	t := &Templates{
		text: map[Template]*texttemplate.Template{},
		html: map[Template]*htmltemplate.Template{},
	}
	for _, name := range AllTemplates {
		file := "templates/" + string(name) + ".tmpl"
		tt, err := texttemplate.New(string(name)).Funcs(funcs).ParseFS(templateFS, "templates/layout.txt.tmpl", file)
		if err != nil {
			return nil, fmt.Errorf("notify: template %s (text): %w", name, err)
		}
		ht, err := htmltemplate.New(string(name)).Funcs(funcs).ParseFS(templateFS, "templates/layout.html.tmpl", file)
		if err != nil {
			return nil, fmt.Errorf("notify: template %s (html): %w", name, err)
		}
		t.text[name], t.html[name] = tt, ht
	}
	return t, nil
}

// Render builds the subject, text and HTML of an e-mail.
func (t *Templates) Render(name Template, data Data) (Message, error) {
	tt, ok := t.text[name]
	if !ok {
		return Message{}, fmt.Errorf("notify: unknown template %q", name)
	}
	var subject, text, html bytes.Buffer
	if err := tt.ExecuteTemplate(&subject, "subject", data); err != nil {
		return Message{}, fmt.Errorf("notify: template %s subject: %w", name, err)
	}
	// A subject is one header line: a line break in it could inject other
	// headers (Bcc: ...). Values come from us, but better safe.
	subj := strings.Join(strings.Fields(subject.String()), " ")

	if err := tt.ExecuteTemplate(&text, "layout.txt", htmlData{Data: data, Subject: subj}); err != nil {
		return Message{}, fmt.Errorf("notify: template %s text: %w", name, err)
	}
	if err := t.html[name].ExecuteTemplate(&html, "layout.html", htmlData{Data: data, Subject: subj}); err != nil {
		return Message{}, fmt.Errorf("notify: template %s html: %w", name, err)
	}
	return Message{Subject: subj, Text: text.String(), HTML: html.String()}, nil
}
