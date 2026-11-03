package notify

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildMIME(t *testing.T) {
	from := &mail.Address{Name: "Oh-My-SSO", Address: "no-reply@sso.example.com"}
	to := &mail.Address{Address: "alice@example.com"}
	in := Message{Subject: "Réinitialiser", Text: "hello\nworld " + strings.Repeat("x", 120), HTML: "<p>hello</p>"}
	raw, err := buildMIME(from, to, in, time.Date(2026, 11, 2, 21, 21, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ReplaceAll(raw, []byte("\r\n"), nil), []byte("\n")) {
		t.Error("a line ends with a bare LF: SMTP wants CRLF")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	h := msg.Header
	for _, k := range []string{"From", "To", "Subject", "Date", "Message-Id", "Mime-Version", "Auto-Submitted"} {
		if h.Get(k) == "" {
			t.Errorf("header %s is missing", k)
		}
	}
	if subj, _ := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); subj != in.Subject {
		t.Errorf("subject = %q, want %q", subj, in.Subject)
	}
	if id := h.Get("Message-Id"); !strings.HasSuffix(id, "@sso.example.com>") {
		t.Errorf("Message-ID %q is not at the sender's domain", id)
	}

	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("Content-Type = %q (%v)", h.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	want := []struct{ ctype, body string }{
		{"text/plain; charset=utf-8", normalizeNewlines(in.Text)},
		{"text/html; charset=utf-8", in.HTML},
	}
	for _, w := range want {
		p, err := mr.NextRawPart()
		if err != nil {
			t.Fatal(err)
		}
		if p.Header.Get("Content-Type") != w.ctype {
			t.Errorf("part Content-Type = %q, want %q", p.Header.Get("Content-Type"), w.ctype)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(p))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != w.body {
			t.Errorf("part %s = %q, want %q", w.ctype, body, w.body)
		}
	}
}

func TestDefaultHeloName(t *testing.T) {
	for from, want := range map[string]string{
		"no-reply@sso.example.com": "sso.example.com",
		"no-reply@localhost":       "localhost",
		"broken":                   "localhost",
	} {
		if got := defaultHeloName(from); got != want {
			t.Errorf("defaultHeloName(%q) = %q, want %q", from, got, want)
		}
	}
	s, err := NewSMTPEmailSender(SMTPConfig{Host: "mail.example.com", From: "SSO <no-reply@example.com>"}, &Templates{})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Config().HeloName; got != "example.com" {
		t.Errorf("default HeloName = %q, want example.com", got)
	}
}
