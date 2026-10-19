package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"time"

	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/core/domain"
)

// IdP metadata (SAML Metadata, OASIS 2005): the XML "business card" a
// service provider imports once: our entity ID, where to send requests, and
// the certificates our signatures verify with.
//
// Every published saml_signing key is listed: the active one, a "pending"
// one (Step 11 two-step rotation: published before it signs) and the
// "rotating" ones still in their grace period. A service provider that
// reloads this document regularly follows rotations by itself.

const (
	metadataValidity = 48 * time.Hour
	metadataCache    = time.Hour
	protocolSAML2    = "urn:oasis:names:tc:SAML:2.0:protocol"
)

func (a *Adapter) handleMetadata(w http.ResponseWriter, r *http.Request) {
	realm, _ := realmFrom(r.Context())
	keys, err := a.core.PublicKeys(r.Context(), realm.ID, domain.SigningKeyPurposeSAMLSigning)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "saml: list signing keys", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var kds []samllib.KeyDescriptor
	for _, k := range keys {
		cert, err := parseCertificatePEM(k.Certificate)
		if err != nil {
			a.logger.WarnContext(r.Context(), "saml: signing key without a usable certificate, not published",
				"kid", k.Kid, "error", err)
			continue
		}
		kds = append(kds, samllib.KeyDescriptor{
			Use: "signing",
			KeyInfo: samllib.KeyInfo{X509Data: samllib.X509Data{
				X509Certificates: []samllib.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}},
			}},
		})
	}
	if len(kds) == 0 {
		// Metadata without a certificate would make every assertion
		// unverifiable: say so plainly instead.
		a.logger.WarnContext(r.Context(), "saml: metadata requested but the realm has no SAML signing key", "realm", realm.Name)
		http.Error(w, errNoSigningKey.Error(), http.StatusServiceUnavailable)
		return
	}

	formats := make([]samllib.NameIDFormat, 0, len(domain.NameIDFormats))
	for _, f := range domain.NameIDFormats {
		formats = append(formats, samllib.NameIDFormat(f))
	}
	ed := &samllib.EntityDescriptor{
		EntityID:      a.entityID(realm),
		ValidUntil:    a.now().UTC().Add(metadataValidity),
		CacheDuration: metadataCache,
		IDPSSODescriptors: []samllib.IDPSSODescriptor{{
			SSODescriptor: samllib.SSODescriptor{
				RoleDescriptor: samllib.RoleDescriptor{
					ProtocolSupportEnumeration: protocolSAML2,
					KeyDescriptors:             kds,
				},
				SingleLogoutServices: []samllib.Endpoint{
					{Binding: bindingRedirect, Location: a.sloURL(realm)},
					{Binding: bindingPOST, Location: a.sloURL(realm)},
				},
				NameIDFormats: formats,
			},
			SingleSignOnServices: []samllib.Endpoint{
				{Binding: bindingRedirect, Location: a.ssoURL(realm)},
				{Binding: bindingPOST, Location: a.ssoURL(realm)},
			},
		}},
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		a.logger.ErrorContext(r.Context(), "saml: marshal metadata", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	// Short: a rotation (pending key) must reach service providers soon.
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}
