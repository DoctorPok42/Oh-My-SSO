package notify

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func renderAll(t *testing.T) map[Template]Message {
	t.Helper()
	templates, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 2, 21, 21, 0, 0, time.UTC)
	out := map[Template]Message{}
	for _, name := range AllTemplates {
		msg, err := templates.Render(name, PreviewData(name, "Oh-My-SSO", now))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = msg
	}
	return out
}

func TestEveryTemplateRenders(t *testing.T) {
	now := time.Date(2026, 11, 2, 21, 21, 0, 0, time.UTC)
	for name, msg := range renderAll(t) {
		data := PreviewData(name, "Oh-My-SSO", now)
		if msg.Subject == "" || strings.ContainsAny(msg.Subject, "\r\n") {
			t.Errorf("%s: bad subject %q", name, msg.Subject)
		}
		for part, body := range map[string]string{"text": msg.Text, "html": msg.HTML} {
			// "<no value>": a field the data does not have; ZgotmplZ: a
			// value html/template refused in that place.
			for _, bad := range []string{"<no value>", "ZgotmplZ", "{{"} {
				if strings.Contains(body, bad) {
					t.Errorf("%s %s: contains %q", name, part, bad)
				}
			}
			// The links must be in both parts: a client showing the text
			// part only still gets them.
			for _, link := range []string{data.ResetURL, data.ForgotPasswordURL} {
				if link != "" && strings.Contains(msg.HTML, link) && !strings.Contains(body, link) {
					t.Errorf("%s %s: link %s missing", name, part, link)
				}
			}
		}
		if !strings.Contains(msg.HTML, "<title>"+msg.Subject+"</title>") {
			t.Errorf("%s: <title> is not the subject", name)
		}
	}
}

// The rules of layout.html.tmpl, checked on every rendered e-mail: what
// breaks in some e-mail clients, and lowers Mailpit's HTML Check score.
func TestTemplatesUseEmailSafeHTML(t *testing.T) {
	style := regexp.MustCompile(`style="([^"]*)"`)
	forbidden := []struct{ re, why string }{
		{`(^|;)\s*display\s*:`, "display is partly supported: use tables"},
		{`(^|;)\s*background\s*:`, "use bgcolor (and background-color), not the background shorthand"},
		{`(^|;)\s*font-weight\s*:`, "use <strong>"},
		{`\bauto\b`, "margin:auto is not supported everywhere: align with tables"},
		{`(^|;)\s*margin\s*:[^;]*-`, "negative margins are not supported everywhere"},
	}
	for name, msg := range renderAll(t) {
		if strings.Contains(msg.HTML, "<body style") {
			t.Errorf("%s: many clients drop the style of <body>: style a table instead", name)
		}
		if !strings.Contains(msg.HTML, "<!--[if mso]>") {
			t.Errorf("%s: the Outlook column is missing", name)
		}
		for _, m := range style.FindAllStringSubmatch(msg.HTML, -1) {
			for _, f := range forbidden {
				if regexp.MustCompile(f.re).MatchString(m[1]) {
					t.Errorf("%s: style %q: %s", name, m[1], f.why)
				}
			}
			// SpamAssassin (HTML_FONT_LOW_CONTRAST) ignores the bgcolor of a
			// cell: white text needs its background color next to it.
			if strings.Contains(m[1], "color:#ffffff") && !strings.Contains(m[1], "background-color:") {
				t.Errorf("%s: style %q: white text without background-color", name, m[1])
			}
		}
	}
}

// SpamAssassin's TVD_PH_SEC ("phrase commonly used in phishing mails")
// matches "your ... account ... security" within a line.
func TestTemplatesAvoidPhishingPhrases(t *testing.T) {
	phishing := regexp.MustCompile(`(?i)\byour .{0,40}account .{0,40}security`)
	tags := regexp.MustCompile(`<[^>]*>`)
	for name, msg := range renderAll(t) {
		for part, body := range map[string]string{"text": msg.Text, "html": tags.ReplaceAllString(msg.HTML, "")} {
			if m := phishing.FindString(body); m != "" {
				t.Errorf("%s %s: %q looks like phishing to spam filters", name, part, m)
			}
		}
	}
}
