package notify

import (
	"context"
	"html"
	"strings"
	"testing"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/i18n"
)

// Every e-mail exists in French, and nothing of the English one is left in
// its subject.
func TestEveryTemplateRendersInFrench(t *testing.T) {
	bundle := i18n.MustDefault()
	templates, err := LoadTemplates(bundle)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 2, 21, 21, 0, 0, time.UTC)
	fr := bundle.Get("fr")
	for _, name := range AllTemplates {
		en, err := templates.Render(name, PreviewData(name, "Oh-My-SSO", now))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := templates.Render(name, PreviewDataIn(fr, name, "Oh-My-SSO", now))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if msg.Subject == en.Subject {
			t.Errorf("%s: subject not translated: %q", name, msg.Subject)
		}
		if !strings.Contains(msg.HTML, `<html lang="fr"`) {
			t.Errorf("%s: <html lang> is not fr", name)
		}
		if !strings.Contains(msg.HTML, "<title>"+html.EscapeString(msg.Subject)+"</title>") {
			t.Errorf("%s: <title> is not the subject", name)
		}
		for part, body := range map[string]string{"text": msg.Text, "html": msg.HTML} {
			for _, bad := range []string{"<no value>", "ZgotmplZ", "{{", "<strong>"} {
				if part == "html" && bad == "<strong>" {
					continue
				}
				if strings.Contains(body, bad) {
					t.Errorf("%s %s: contains %q", name, part, bad)
				}
			}
		}
	}
	msg, _ := templates.Render(TemplatePasswordReset, PreviewDataIn(fr, TemplatePasswordReset, "Oh-My-SSO", now))
	for _, want := range []string{"Bonjour alice,", "expire dans <strong>30 minutes</strong>", "lun. 2 nov. 2026, 21:21 UTC", "Firefox sous Windows"} {
		if !strings.Contains(msg.HTML, want) {
			t.Errorf("password_reset in French: no %q", want)
		}
	}
}

type settingsStub struct {
	repository.InstanceSettingsRepository
	locale string
}

func (s settingsStub) GetByRealmID(context.Context, string) (*domain.InstanceSettings, error) {
	if s.locale == "" {
		return nil, repository.ErrNotFound
	}
	return &domain.InstanceSettings{DefaultLocale: s.locale}, nil
}

// The language of an e-mail: the account's, else the realm's default, else
// English.
func TestDispatcherLanguage(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		profile map[string]any
		realm   string
		want    string
	}{
		{"the account's language", map[string]any{"locale": "fr"}, "en", "fr"},
		{"the realm's default", nil, "fr", "fr"},
		{"an unknown language: the realm's", map[string]any{"locale": "xx"}, "fr", "fr"},
		{"nothing: English", nil, "", "en"},
	} {
		d := NewDispatcher(DispatcherConfig{}, DispatcherDeps{Settings: settingsStub{locale: c.realm}})
		got := d.localizer(ctx, &domain.User{Profile: c.profile}, "r1").Lang()
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
