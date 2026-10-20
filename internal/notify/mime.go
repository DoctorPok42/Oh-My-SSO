package notify

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// buildMIME turns a Message into the bytes sent after the SMTP DATA command
// (RFC 5322 message, MIME RFC 2045-2049):
//
//	From, To, Subject, Date, Message-ID, MIME-Version...   headers
//	Content-Type: multipart/alternative; boundary=...
//	  ├─ text/plain; charset=utf-8   (quoted-printable)
//	  └─ text/html;  charset=utf-8   (quoted-printable)
//
// multipart/alternative = "the same content twice, pick the best one": the
// mail client shows the HTML part, or the text part if it cannot (or the
// user prefers text). Sending both also scores better with spam filters.
//
// https://datatracker.ietf.org/doc/html/rfc5322
// https://datatracker.ietf.org/doc/html/rfc2046#section-5.1.4
func buildMIME(from, to *mail.Address, msg Message, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	h := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	h("From", from.String()) // mail.Address.String() encodes non-ASCII names (RFC 2047)
	h("To", to.String())
	h("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", messageID(from.Address))
	h("MIME-Version", "1.0")
	// RFC 3834: tells mail servers and vacation responders this is an
	// automatic message, so they do not answer it.
	h("Auto-Submitted", "auto-generated")
	h("X-Auto-Response-Suppress", "All")
	h("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	buf.WriteString("\r\n")

	for _, part := range []struct{ ctype, body string }{
		{"text/plain; charset=utf-8", msg.Text},
		{"text/html; charset=utf-8", msg.HTML},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		// quoted-printable keeps lines short (SMTP limit: 998 characters)
		// and survives servers that only accept 7-bit data.
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(normalizeNewlines(part.body))); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalizeNewlines uses CRLF everywhere, as SMTP and MIME require.
func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// messageID is a unique id for the message, at the sender's domain.
func messageID(fromAddress string) string {
	domain := "localhost"
	if i := strings.LastIndexByte(fromAddress, '@'); i >= 0 && i < len(fromAddress)-1 {
		domain = fromAddress[i+1:]
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "<" + hex.EncodeToString(b) + "@" + domain + ">"
}
