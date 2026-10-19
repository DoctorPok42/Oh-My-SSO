package domain

import (
	"fmt"
	"time"
)

// ClientCertificate is one entry of ClientApp.ClientCertificates (SAML,
// Step 11): a certificate of the service provider, used to check the
// signature of the requests it sends (AuthnRequest, LogoutRequest).
//
// It is a list, not a single field, so that a service provider can change
// its certificate without downtime: register the new one with a NotBefore,
// give the old one a NotAfter, and both are accepted in between.
//
// Stored as JSON: {"certificate": "<PEM>", "not_before": "<RFC 3339>",
// "not_after": "<RFC 3339>"}; both dates are optional.
type ClientCertificate struct {
	PEM       string
	NotBefore time.Time // zero: no lower bound
	NotAfter  time.Time // zero: no upper bound
}

// ActiveAt reports whether the administrator's validity window includes t.
// (The certificate's own X.509 dates are checked separately.)
func (c ClientCertificate) ActiveAt(t time.Time) bool {
	if !c.NotBefore.IsZero() && t.Before(c.NotBefore) {
		return false
	}
	if !c.NotAfter.IsZero() && !t.Before(c.NotAfter) {
		return false
	}
	return true
}

// ToMap is the JSON form stored in client_certificates.
func (c ClientCertificate) ToMap() map[string]interface{} {
	m := map[string]interface{}{"certificate": c.PEM}
	if !c.NotBefore.IsZero() {
		m["not_before"] = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		m["not_after"] = c.NotAfter.UTC().Format(time.RFC3339)
	}
	return m
}

// Certificates parses ClientCertificates. An entry that cannot be read is
// an error: a typo in a date must not silently widen or close a window.
func (c *ClientApp) Certificates() ([]ClientCertificate, error) {
	out := make([]ClientCertificate, 0, len(c.ClientCertificates))
	for i, raw := range c.ClientCertificates {
		cert, _ := raw["certificate"].(string)
		if cert == "" {
			return nil, fmt.Errorf("client_certificates[%d]: missing certificate", i)
		}
		cc := ClientCertificate{PEM: cert}
		for key, dst := range map[string]*time.Time{"not_before": &cc.NotBefore, "not_after": &cc.NotAfter} {
			v, ok := raw[key]
			if !ok || v == nil || v == "" {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("client_certificates[%d].%s: not a string", i, key)
			}
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return nil, fmt.Errorf("client_certificates[%d].%s: %w", i, key, err)
			}
			*dst = t
		}
		out = append(out, cc)
	}
	return out, nil
}
