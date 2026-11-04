// Package i18n translates what the IdP shows and sends: the sign-in pages
// (loginui), the account console (accountui) and the e-mails (notify).
//
// English is the language of the code: every text is written, in English,
// where it is used, next to a key that names it:
//
//	{{t "login.title.sign_in" "Sign in"}}                              templates
//	loc.T("account.flash.profile_saved", "Your name was saved.")     Go
//	t("login.js.error.invalid_credentials", "Wrong username or password.")  JavaScript
//
// So English needs no file, and a text missing from a translation falls
// back to it. Every other language is one flat JSON file, key -> text, like
// the admin translations of Strapi (src/admin/translations/fr.json):
//
//	{
//	  "language.name": "Français",
//	  "login.title.sign_in": "Se connecter",
//	  "login.subtitle.continue_to": "pour continuer vers {client}"
//	}
//
// Values may hold placeholders, {name}, replaced by the arguments of T
// (name/value pairs). A text that depends on a number has two keys, one
// per plural form (key.one, key.other): see Localizer.N.
//
// The files of this package (locales/<lang>.json) are compiled into the
// binary. LOCALES_DIR (Load) adds languages, or changes texts of the
// built-in ones, without a rebuild: <dir>/<lang>.json is read at start-up
// and its keys override the embedded ones.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// English is the language of the code, always available.
const English = "en"

//go:embed locales/*.json
var embedded embed.FS

// Language is one language the server can show.
type Language struct {
	Tag  string `json:"tag"`  // BCP 47, lower case: "en", "fr", "pt-br"
	Name string `json:"name"` // in that language: "Français"
}

// Bundle holds every language. It is read-only once loaded: safe for
// concurrent use.
type Bundle struct {
	catalogs map[string]map[string]string // tag -> key -> text ("en": empty)
	langs    []Language                   // English first, then by tag
}

// Load reads the embedded translations, then the <lang>.json files of dir
// (LOCALES_DIR, "" for none) over them. A file that is not valid JSON, or a
// file name that is not a language tag, fails: better at start-up than a
// page in the wrong language later.
func Load(dir string) (*Bundle, error) {
	b := &Bundle{catalogs: map[string]map[string]string{English: {}}}
	if err := b.addFS(embedded, "locales"); err != nil {
		return nil, err
	}
	if dir != "" {
		if err := b.addFS(os.DirFS(dir), "."); err != nil {
			return nil, fmt.Errorf("i18n: LOCALES_DIR %s: %w", dir, err)
		}
	}
	b.index()
	return b, nil
}

// MustDefault returns the embedded languages only (tests, tools). It panics
// if they cannot be read, which is a bug of this package.
func MustDefault() *Bundle {
	b, err := Load("")
	if err != nil {
		panic(err)
	}
	return b
}

func (b *Bundle) addFS(fsys fs.FS, root string) error {
	files, err := fs.Glob(fsys, filepath.ToSlash(filepath.Join(root, "*.json")))
	if err != nil {
		return err
	}
	for _, f := range files {
		tag := Normalize(strings.TrimSuffix(filepath.Base(f), ".json"))
		if !validTag(tag) {
			return fmt.Errorf("i18n: %s: the file name must be a language tag (fr.json, pt-br.json)", f)
		}
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return err
		}
		var msgs map[string]string
		if err := json.Unmarshal(raw, &msgs); err != nil {
			return fmt.Errorf("i18n: %s: %w", f, err)
		}
		cat := b.catalogs[tag]
		if cat == nil {
			cat = map[string]string{}
			b.catalogs[tag] = cat
		}
		for k, v := range msgs {
			if v != "" {
				cat[k] = v
			}
		}
	}
	return nil
}

func (b *Bundle) index() {
	b.langs = []Language{{Tag: English, Name: "English"}}
	var tags []string
	for tag := range b.catalogs {
		if tag != English {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	for _, tag := range tags {
		name := b.catalogs[tag]["language.name"]
		if name == "" {
			name = tag
		}
		b.langs = append(b.langs, Language{Tag: tag, Name: name})
	}
}

// Languages lists the available languages, English first.
func (b *Bundle) Languages() []Language {
	return append([]Language(nil), b.langs...)
}

// Normalize writes a language tag the way the files are named: lower case,
// "-" between the parts ("pt_BR" -> "pt-br").
func Normalize(tag string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(tag), "_", "-"))
}

func validTag(tag string) bool {
	if len(tag) < 2 || len(tag) > 35 {
		return false
	}
	for i, part := range strings.Split(tag, "-") {
		if part == "" || len(part) > 8 || (i == 0 && len(part) > 3) {
			return false
		}
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// Match returns the available language for a tag: the tag itself, else its
// base language ("fr-CA" -> "fr"). "" when neither is available.
func (b *Bundle) Match(tag string) string {
	tag = Normalize(tag)
	if tag == "" {
		return ""
	}
	if _, ok := b.catalogs[tag]; ok {
		return tag
	}
	if base, _, ok := strings.Cut(tag, "-"); ok {
		if _, ok := b.catalogs[base]; ok {
			return base
		}
	}
	return ""
}

// Supported reports whether a tag matches an available language.
func (b *Bundle) Supported(tag string) bool { return b.Match(tag) != "" }

// Get returns the texts of a language (Match first), English if it is not
// available.
func (b *Bundle) Get(tag string) *Localizer {
	lang := b.Match(tag)
	if lang == "" {
		lang = English
	}
	return &Localizer{lang: lang, msgs: b.catalogs[lang]}
}

// Localizer gives the texts of one language. The zero value (and nil) is
// English.
type Localizer struct {
	lang string
	msgs map[string]string
}

// Lang is the language tag ("en" for the zero value).
func (l *Localizer) Lang() string {
	if l == nil || l.lang == "" {
		return English
	}
	return l.lang
}

func (l *Localizer) lookup(key, def string) string {
	if l != nil {
		if v, ok := l.msgs[key]; ok {
			return v
		}
	}
	return def
}

// T returns the text of key in this language, else def (the English text),
// with its placeholders replaced: args are name/value pairs,
// T("k", "Hello {name}", "name", "Ada").
func (l *Localizer) T(key, def string, args ...any) string {
	return fill(l.lookup(key, def), args, false)
}

// N is T for a text that depends on a number n: key.one or key.other in the
// files, one or other in English. {count} is n.
func (l *Localizer) N(key string, n int, one, other string, args ...any) string {
	args = append([]any{"count", n}, args...)
	if l.pluralOne(n) {
		return fill(l.lookup(key+".one", one), args, false)
	}
	return fill(l.lookup(key+".other", other), args, false)
}

// HTML is T for HTML: the text is escaped, except for <strong>, </strong>
// and <br>, which a translation may use for emphasis; the arguments are
// always escaped.
func (l *Localizer) HTML(key, def string, args ...any) template.HTML {
	return template.HTML(fill(allowTags(html.EscapeString(l.lookup(key, def))), args, true)) // #nosec G203 -- escaped above, only fixed tags restored
}

var allowedTags = strings.NewReplacer(
	"&lt;strong&gt;", "<strong>", "&lt;/strong&gt;", "</strong>", "&lt;br&gt;", "<br>",
)

func allowTags(s string) string { return allowedTags.Replace(s) }

// pluralOne: whether n takes the singular form. French and the languages
// alike count 0 as singular ("0 code restant"), English does not.
func (l *Localizer) pluralOne(n int) bool {
	base, _, _ := strings.Cut(l.Lang(), "-")
	switch base {
	case "fr", "pt", "hi", "fa", "hy", "kab":
		return n == 0 || n == 1
	}
	return n == 1
}

func fill(s string, args []any, escape bool) string {
	if len(args) < 2 || !strings.Contains(s, "{") {
		return s
	}
	pairs := make([]string, 0, len(args))
	for i := 0; i+1 < len(args); i += 2 {
		v := fmt.Sprint(args[i+1])
		if escape {
			v = html.EscapeString(v)
		}
		pairs = append(pairs, "{"+fmt.Sprint(args[i])+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// Messages returns the texts whose key starts with prefix (the strings a
// script needs, see the pages' omsso-i18n block). Empty for English: the
// script has its English texts.
func (l *Localizer) Messages(prefix string) map[string]string {
	out := map[string]string{}
	if l == nil {
		return out
	}
	for k, v := range l.msgs {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out
}

// --- dates and durations ---------------------------------------------------

const (
	defMonths   = "Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec"
	defWeekdays = "Sun,Mon,Tue,Wed,Thu,Fri,Sat"
)

func (l *Localizer) dateParts(t time.Time) []any {
	t = t.UTC()
	months := strings.Split(l.lookup("date.months", defMonths), ",")
	days := strings.Split(l.lookup("date.weekdays", defWeekdays), ",")
	month, day := t.Format("Jan"), t.Format("Mon")
	if len(months) == 12 {
		month = strings.TrimSpace(months[t.Month()-1])
	}
	if len(days) == 7 {
		day = strings.TrimSpace(days[t.Weekday()])
	}
	return []any{"month", month, "weekday", day, "day", t.Day(), "year", t.Year(), "time", t.Format("15:04")}
}

// Date: "Jan 2, 2006" in English, in UTC.
func (l *Localizer) Date(t time.Time) string {
	return fill(l.lookup("date.format.date", "{month} {day}, {year}"), l.dateParts(t), false)
}

// DateTime: "Jan 2, 2006, 15:04 UTC" in English.
func (l *Localizer) DateTime(t time.Time) string {
	return fill(l.lookup("date.format.datetime", "{month} {day}, {year}, {time} UTC"), l.dateParts(t), false)
}

// LongDateTime: "Mon 2 Jan 2006, 15:04 UTC" in English (e-mails).
func (l *Localizer) LongDateTime(t time.Time) string {
	return fill(l.lookup("date.format.long", "{weekday} {day} {month} {year}, {time} UTC"), l.dateParts(t), false)
}

// Duration: "30 minutes", "1 hour", "2 hours 30 minutes", rounded to the
// minute, at least one.
func (l *Localizer) Duration(d time.Duration) string {
	m := int((d + 30*time.Second) / time.Minute)
	if m < 1 {
		m = 1
	}
	h, m := m/60, m%60
	hours := l.N("duration.hours", h, "{count} hour", "{count} hours")
	minutes := l.N("duration.minutes", m, "{count} minute", "{count} minutes")
	switch {
	case h == 0:
		return minutes
	case m == 0:
		return hours
	default:
		return l.T("duration.hours_minutes", "{hours} {minutes}", "hours", hours, "minutes", minutes)
	}
}

// FuncMap is what the templates call:
//
//	{{t "key" "English" "name" .Value}}       a text (escaped by html/template)
//	{{tn "key" .Count "one" "other"}}         a text that depends on a number
//	{{th "key" "English with <strong>x</strong>"}}  a text with emphasis
//	{{tp "key" "English with <strong>x</strong>"}}  the same, as plain text
//	{{lang}}                                  the language tag (<html lang>)
//	{{date .}} {{datetime .}}                 a time, in this language
func (l *Localizer) FuncMap() map[string]any {
	return map[string]any{
		"t":        l.T,
		"tn":       l.N,
		"th":       l.HTML,
		"tp":       l.Plain,
		"lang":     l.Lang,
		"date":     l.Date,
		"datetime": l.DateTime,
		"jsmsgs":   l.Messages,
		"text":     l.Text,
	}
}

// Text is a text to translate once the language is known (a message
// defined in a package variable, before any request).
type Text struct {
	Key     string
	Default string // English
	Args    []any  // name/value pairs, as for T
}

// M makes a Text: M("message.expired.title", "This sign-in link has expired").
func M(key, def string, args ...any) Text { return Text{Key: key, Default: def, Args: args} }

// Text translates t.
func (l *Localizer) Text(t Text) string { return l.T(t.Key, t.Default, t.Args...) }

var plainTags = strings.NewReplacer("<strong>", "", "</strong>", "", "<br>", "\n")

// Plain is T for plain text (the text version of an e-mail) of a text that
// may hold the tags HTML allows: they are removed (<br> is a line break).
func (l *Localizer) Plain(key, def string, args ...any) string {
	return fill(plainTags.Replace(l.lookup(key, def)), args, false)
}
