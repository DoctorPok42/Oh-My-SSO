package httpserver

import (
	"net/http"
	"strings"
	"time"
)

// securityTxtContact turns SECURITY_CONTACT into the URI RFC 9116 wants: a
// bare address becomes mailto:. Anything with a line break is refused, since
// the file is line-based.
func securityTxtContact(contact string) string {
	contact = strings.TrimSpace(contact)
	if contact == "" || strings.ContainsAny(contact, "\r\n") {
		return ""
	}
	if !strings.Contains(contact, ":") && strings.Contains(contact, "@") {
		return "mailto:" + contact
	}
	return contact
}

// mountSecurityTxt serves /.well-known/security.txt when the operator set a
// contact. Expires is always a year ahead, so the file never goes stale.
func (s *Server) mountSecurityTxt() {
	contact := securityTxtContact(s.securityContact)
	if contact == "" {
		return
	}
	s.router.Get("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Contact: " + contact + "\nExpires: " + time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339) + "\nPreferred-Languages: en, fr\n"))
	})
}
