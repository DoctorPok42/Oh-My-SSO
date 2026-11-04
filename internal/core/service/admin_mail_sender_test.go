package service

import (
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

func TestNormalizeMailSender(t *testing.T) {
	valid := SettingsPatch{
		MailFromName:    strp("  Acme Support "),
		MailFromAddress: strp(" no-reply@acme.example "),
		MailReplyTo:     strp("help@acme.example"),
		MailLogoURL:     strp(" https://acme.example/logo.png "),
	}
	if err := normalizeMailSender(&valid); err != nil {
		t.Fatalf("valid sender refused: %v", err)
	}
	if *valid.MailFromName != "Acme Support" || *valid.MailFromAddress != "no-reply@acme.example" ||
		*valid.MailLogoURL != "https://acme.example/logo.png" {
		t.Errorf("values not trimmed: %q %q %q", *valid.MailFromName, *valid.MailFromAddress, *valid.MailLogoURL)
	}

	// Empty = back to the server default; nil = unchanged.
	cleared := SettingsPatch{MailFromName: strp(""), MailFromAddress: strp(""), MailReplyTo: strp(""), MailLogoURL: strp("")}
	if err := normalizeMailSender(&cleared); err != nil {
		t.Errorf("clearing the sender refused: %v", err)
	}
	if err := normalizeMailSender(&SettingsPatch{}); err != nil {
		t.Errorf("empty patch refused: %v", err)
	}

	for name, p := range map[string]SettingsPatch{
		"name with a line break":      {MailFromName: strp("Acme\r\nBcc: evil@example.com")},
		"name too long":               {MailFromName: strp(strings.Repeat("a", maxMailFromName+1))},
		"address with a display name": {MailFromAddress: strp("Acme <no-reply@acme.example>")},
		"address not an address":      {MailFromAddress: strp("not an address")},
		"reply-to with a header":      {MailReplyTo: strp("a@b.example\r\nBcc: evil@example.com")},
		"logo over http":              {MailLogoURL: strp("http://acme.example/logo.png")},
		"logo is a data URL":          {MailLogoURL: strp("data:image/png;base64,AAAA")},
		"logo without a host":         {MailLogoURL: strp("https:///logo.png")},
		"logo javascript scheme":      {MailLogoURL: strp("javascript:alert(1)")},
		"logo too long":               {MailLogoURL: strp("https://acme.example/" + strings.Repeat("a", maxMailLogoURL))},
	} {
		if err := normalizeMailSender(&p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
