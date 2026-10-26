package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"

	samllib "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"

	"sso.internal/sso/internal/core/domain"
)

type SPMetadata struct {
	EntityID string
	// ACSURL: the HTTP-POST AssertionConsumerService (the default one, else
	// the lowest index). Responses only use HTTP-POST.
	ACSURL string
	// SLOURL: the HTTP-Redirect SingleLogoutService, the binding we use to
	// send logout messages. Empty if the provider has none.
	SLOURL string
	// Certificates (base64 DER) of the signing keys: KeyDescriptors with
	// use="signing" or no use. Encryption-only ones are skipped.
	Certificates []string
	// NameIDFormat: the first listed format we support, if any.
	NameIDFormat        string
	AuthnRequestsSigned bool
	// Warnings: things the administrator should know (ignored endpoints...).
	Warnings []string
}

// ParseSPMetadata reads an <EntityDescriptor> (or an <EntitiesDescriptor>
// holding exactly one) with an <SPSSODescriptor>.
func ParseSPMetadata(data []byte) (*SPMetadata, error) {
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	var ed samllib.EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		var list samllib.EntitiesDescriptor
		if err2 := xml.Unmarshal(data, &list); err2 != nil || len(list.EntityDescriptors) != 1 {
			return nil, fmt.Errorf("saml metadata: expected one EntityDescriptor: %w", err)
		}
		ed = list.EntityDescriptors[0]
	}
	if ed.EntityID == "" {
		return nil, errors.New("saml metadata: entityID is missing")
	}
	if len(ed.SPSSODescriptors) == 0 {
		return nil, errors.New("saml metadata: no SPSSODescriptor (is this an IdP's metadata?)")
	}
	sp := ed.SPSSODescriptors[0]
	if !strings.Contains(sp.ProtocolSupportEnumeration, protocolSAML2) {
		return nil, errors.New("saml metadata: the service provider does not support SAML 2.0")
	}
	out := &SPMetadata{EntityID: ed.EntityID}
	if len(ed.SPSSODescriptors) > 1 {
		out.Warnings = append(out.Warnings, "several SPSSODescriptor elements: only the first one is used")
	}
	if sp.AuthnRequestsSigned != nil {
		out.AuthnRequestsSigned = *sp.AuthnRequestsSigned
	}

	// ACS: HTTP-POST only, default first, then lowest index.
	var acs []samllib.IndexedEndpoint
	for _, e := range sp.AssertionConsumerServices {
		if e.Binding == bindingPOST {
			acs = append(acs, e)
		} else {
			out.Warnings = append(out.Warnings, fmt.Sprintf("ACS %s (%s) ignored: responses are only sent with HTTP-POST", e.Location, e.Binding))
		}
	}
	slices.SortStableFunc(acs, func(x, y samllib.IndexedEndpoint) int {
		dx, dy := x.IsDefault != nil && *x.IsDefault, y.IsDefault != nil && *y.IsDefault
		switch {
		case dx && !dy:
			return -1
		case dy && !dx:
			return 1
		}
		return x.Index - y.Index
	})
	if len(acs) == 0 {
		return nil, errors.New("saml metadata: no AssertionConsumerService with the HTTP-POST binding")
	}
	out.ACSURL = acs[0].Location
	if len(acs) > 1 {
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d HTTP-POST ACS endpoints: only %s is registered", len(acs), out.ACSURL))
	}

	for _, e := range sp.SingleLogoutServices {
		if e.Binding == bindingRedirect && out.SLOURL == "" {
			out.SLOURL = e.Location
		}
	}
	if out.SLOURL == "" && len(sp.SingleLogoutServices) > 0 {
		out.Warnings = append(out.Warnings, "no SingleLogoutService with the HTTP-Redirect binding: single logout will not reach this provider")
	}

	for _, kd := range sp.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			data := strings.Join(strings.Fields(c.Data), "")
			if data != "" && !slices.Contains(out.Certificates, data) {
				out.Certificates = append(out.Certificates, data)
			}
		}
	}

	for _, f := range sp.NameIDFormats {
		if slices.Contains(domain.NameIDFormats, string(f)) {
			out.NameIDFormat = string(f)
			break
		}
	}
	return out, nil
}
