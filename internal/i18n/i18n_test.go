package i18n

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLanguages(t *testing.T) {
	b := MustDefault()
	langs := b.Languages()
	if langs[0] != (Language{Tag: "en", Name: "English"}) {
		t.Fatalf("English must come first: %v", langs)
	}
	if !b.Supported("fr") || b.Get("fr").Lang() != "fr" {
		t.Fatal("the French file is embedded")
	}
	for in, want := range map[string]string{
		"fr": "fr", "FR": "fr", "fr-CA": "fr", "fr_ca": "fr", "en-GB": "en", "de": "", "": "", "../fr": "",
	} {
		if got := b.Match(in); got != want {
			t.Errorf("Match(%q) = %q, want %q", in, got, want)
		}
	}
	if b.Get("klingon").Lang() != English {
		t.Error("an unknown language falls back to English")
	}
}

func TestT(t *testing.T) {
	fr := MustDefault().Get("fr")
	if got := fr.T("login.title.sign_in", "Sign in"); got != "Se connecter" {
		t.Errorf("got %q", got)
	}
	if got := fr.T("no.such.key", "Hello {name}", "name", "Ada"); got != "Hello Ada" {
		t.Errorf("a missing key falls back to English: %q", got)
	}
	var nilLoc *Localizer
	if got := nilLoc.T("login.title.sign_in", "Sign in"); got != "Sign in" {
		t.Errorf("nil is English: %q", got)
	}
	if got := fr.T("consent.title", "", "client", "Grafana"); got != "Autoriser Grafana à accéder à votre compte ?" {
		t.Errorf("placeholder: %q", got)
	}
}

func TestN(t *testing.T) {
	b := MustDefault()
	en, fr := b.Get("en"), b.Get("fr")
	for _, c := range []struct {
		loc  *Localizer
		n    int
		want string
	}{
		{en, 0, "0 hours"}, {en, 1, "1 hour"}, {en, 2, "2 hours"},
		{fr, 0, "0 heure"}, {fr, 1, "1 heure"}, {fr, 2, "2 heures"},
	} {
		if got := c.loc.N("duration.hours", c.n, "{count} hour", "{count} hours"); got != c.want {
			t.Errorf("%s N(%d) = %q, want %q", c.loc.Lang(), c.n, got, c.want)
		}
	}
	if got := fr.Duration(150 * time.Minute); got != "2 heures 30 minutes" {
		t.Errorf("duration: %q", got)
	}
	if got := en.Duration(time.Minute); got != "1 minute" {
		t.Errorf("duration: %q", got)
	}
}

func TestHTML(t *testing.T) {
	en := MustDefault().Get("en")
	got := string(en.HTML("x", "to <strong>{client}</strong> <em>x</em>", "client", "<script>"))
	if want := "to <strong>&lt;script&gt;</strong> &lt;em&gt;x&lt;/em&gt;"; got != want {
		t.Errorf("only <strong> and <br> survive, arguments are escaped:\n got %q\nwant %q", got, want)
	}
	if got := en.Plain("x", "<strong>Was it you?</strong> Wait"); got != "Was it you? Wait" {
		t.Errorf("plain: %q", got)
	}
}

func TestDates(t *testing.T) {
	b := MustDefault()
	at := time.Date(2026, time.November, 3, 14, 5, 0, 0, time.UTC)
	if got := b.Get("en").DateTime(at); got != "Nov 3, 2026, 14:05 UTC" {
		t.Errorf("en: %q", got)
	}
	if got := b.Get("fr").Date(at); got != "3 nov. 2026" {
		t.Errorf("fr: %q", got)
	}
	if got := b.Get("en").LongDateTime(at); got != "Tue 3 Nov 2026, 14:05 UTC" {
		t.Errorf("en long: %q", got)
	}
	if got := b.Get("fr").LongDateTime(at); got != "mar. 3 nov. 2026, 14:05 UTC" {
		t.Errorf("fr long: %q", got)
	}
}

func TestPick(t *testing.T) {
	b := MustDefault()
	str := func(s string) func() string { return func() string { return s } }
	for _, c := range []struct {
		name string
		p    Prefs
		want string
	}{
		{"nothing: English", Prefs{}, "en"},
		{"realm default", Prefs{Realm: str("fr")}, "fr"},
		{"browser before realm", Prefs{Browser: "en", Realm: str("fr")}, "en"},
		{"ui_locales before browser", Prefs{Hints: []string{"de", "fr-CA"}, Browser: "en"}, "fr"},
		{"the user's choice first", Prefs{User: str("fr"), Hints: []string{"en"}, Browser: "en"}, "fr"},
		{"an unknown choice is skipped", Prefs{User: str("de"), Browser: "fr"}, "fr"},
	} {
		if got := b.Pick(c.p); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	// The lookups are lazy: not called when an earlier preference matches.
	called := false
	b.Pick(Prefs{User: str("fr"), Realm: func() string { called = true; return "en" }})
	if called {
		t.Error("the realm default is not looked up when the user chose")
	}
	ctx := WithUser(WithPrefs(context.Background(), Prefs{Browser: "en"}), "fr")
	if b.For(ctx).Lang() != "fr" {
		t.Error("WithUser")
	}
}

func TestCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: Cookie, Value: "FR"})
	if got := FromCookie(r); got != "fr" {
		t.Errorf("got %q", got)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: Cookie, Value: "<script>"})
	if got := FromCookie(r); got != "" {
		t.Errorf("not a tag: %q", got)
	}
}

// LOCALES_DIR adds a language and changes texts of a built-in one.
func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("de.json", `{"language.name": "Deutsch", "login.title.sign_in": "Anmelden"}`)
	write("fr.json", `{"login.title.sign_in": "Connexion"}`)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Get("de").T("login.title.sign_in", "Sign in"); got != "Anmelden" {
		t.Errorf("de: %q", got)
	}
	if got := b.Get("fr").T("login.title.sign_in", "Sign in"); got != "Connexion" {
		t.Errorf("an override: %q", got)
	}
	if got := b.Get("fr").T("login.submit", "Sign in"); got != "Se connecter" {
		t.Errorf("the other embedded texts stay: %q", got)
	}
	if langs := b.Languages(); len(langs) != 3 || langs[1].Name != "Deutsch" {
		t.Errorf("languages: %v", langs)
	}

	write("bad name!.json", `{}`)
	if _, err := Load(dir); err == nil {
		t.Error("a file name that is not a tag is refused")
	}
	_ = os.Remove(filepath.Join(dir, "bad name!.json"))
	write("es.json", `{not json`)
	if _, err := Load(dir); err == nil {
		t.Error("invalid JSON is refused")
	}
}
