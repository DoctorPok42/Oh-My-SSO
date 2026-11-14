package notify

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"

	"sso.internal/sso/internal/i18n"
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
	// Lang: the language of the e-mail (package i18n), "" for English. The
	// dispatcher picks the recipient's (their account's, else the realm's
	// default) and writes the other fields in it.
	Lang string

	// Sender: the realm's sender settings. LogoURL: its https image, shown
	// in the header of the e-mail in place of the product initial.
	Sender  Sender
	LogoURL string

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

	AppName        string
	AppAccess      []string
	AppAccessAdded bool

	RecoveryKind    string
	RecoveryActor   string
	RecoveryAccount string

	// user_import_finished. ImportNotDone: lines the import never reached,
	// because it was interrupted.
	ImportRealm       string
	ImportFile        string
	ImportTotal       int
	ImportCreated     int
	ImportFailed      int
	ImportNotDone     int
	ImportInterrupted bool
	ImportURL         string // the report in the admin console

	// email_verification: the link that confirms the address (ExpiresIn:
	// how long it works).
	VerifyURL string
}

type htmlData struct {
	Data
	Subject string
}

type buttonData struct{ URL, Label string }

var funcs = map[string]any{
	"button": func(url, label string) buttonData { return buttonData{URL: url, Label: label} },

	// Conditional comments that only Outlook for Windows reads (it renders
	// with Word, which ignores max-width and does not always inherit fonts).
	// html/template removes the comments written in a template, so they come
	// from these functions; their content is fixed, nothing is interpolated.
	"outlookHead": func() htmltemplate.HTML {
		return `<!--[if mso]><style>table{mso-table-lspace:0pt;mso-table-rspace:0pt;}td,p,a,h1,li,strong{font-family:'Segoe UI',Arial,sans-serif;}</style><![endif]-->`
	},
	"outlookColumnStart": func() htmltemplate.HTML {
		return `<!--[if mso]><table role="presentation" width="560" align="center" cellpadding="0" cellspacing="0"><tr><td><![endif]-->`
	},
	"outlookColumnEnd": func() htmltemplate.HTML {
		return `<!--[if mso]></td></tr></table><![endif]-->`
	},
}

// Templates holds every e-mail, parsed once per language (the templates
// call {{t "key" "English text"}}, package i18n).
type Templates struct {
	i18n *i18n.Bundle
	text map[string]map[Template]*texttemplate.Template // language -> e-mail
	html map[string]map[Template]*htmltemplate.Template
}

// LoadTemplates parses the embedded templates in every language of the
// bundle (nil: the embedded languages).
func LoadTemplates(bundle *i18n.Bundle) (*Templates, error) {
	if bundle == nil {
		bundle = i18n.MustDefault()
	}
	t := &Templates{
		i18n: bundle,
		text: map[string]map[Template]*texttemplate.Template{},
		html: map[string]map[Template]*htmltemplate.Template{},
	}
	for _, l := range bundle.Languages() {
		if err := t.load(l.Tag); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *Templates) load(lang string) error {
	fm := map[string]any{}
	for k, v := range funcs {
		fm[k] = v
	}
	for k, v := range t.i18n.Get(lang).FuncMap() {
		fm[k] = v
	}
	text, html := map[Template]*texttemplate.Template{}, map[Template]*htmltemplate.Template{}
	for _, name := range AllTemplates {
		file := "templates/" + string(name) + ".tmpl"
		tt, err := texttemplate.New(string(name)).Funcs(fm).ParseFS(templateFS, "templates/layout.txt.tmpl", file)
		if err != nil {
			return fmt.Errorf("notify: template %s (text, %s): %w", name, lang, err)
		}
		ht, err := htmltemplate.New(string(name)).Funcs(fm).ParseFS(templateFS, "templates/layout.html.tmpl", file)
		if err != nil {
			return fmt.Errorf("notify: template %s (html, %s): %w", name, lang, err)
		}
		text[name], html[name] = tt, ht
	}
	t.text[lang], t.html[lang] = text, html
	return nil
}

// Render builds the subject, text and HTML of an e-mail.
func (t *Templates) Render(name Template, data Data) (Message, error) {
	lang := t.i18n.Match(data.Lang)
	if lang == "" {
		lang = i18n.English
	}
	tt, ok := t.text[lang][name]
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
	if err := t.html[lang][name].ExecuteTemplate(&html, "layout.html", htmlData{Data: data, Subject: subj}); err != nil {
		return Message{}, fmt.Errorf("notify: template %s html: %w", name, err)
	}
	return Message{Subject: subj, Text: text.String(), HTML: html.String()}, nil
}
