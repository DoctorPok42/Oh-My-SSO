package saml

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"sso.internal/sso/internal/core/domain"
)


var (
	errUnsigned     = errors.New("saml: the message must be signed")
	errBadSignature = errors.New("saml: signature verification failed")
	errWeakAlgo     = errors.New("saml: signature algorithm refused (SHA-1 and unknown algorithms are not accepted)")
)

// Accepted signature algorithms. SHA-1 is not: collisions are practical
// since 2017 (SHAttered), and every current SAML stack defaults to SHA-256.
var signatureHashes = map[string]crypto.Hash{
	dsig.RSASHA256SignatureMethod:   crypto.SHA256,
	dsig.RSASHA384SignatureMethod:   crypto.SHA384,
	dsig.RSASHA512SignatureMethod:   crypto.SHA512,
	dsig.ECDSASHA256SignatureMethod: crypto.SHA256,
	dsig.ECDSASHA384SignatureMethod: crypto.SHA384,
	dsig.ECDSASHA512SignatureMethod: crypto.SHA512,
}

var digestAlgorithms = map[string]bool{
	"http://www.w3.org/2001/04/xmlenc#sha256":       true,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
	"http://www.w3.org/2001/04/xmlenc#sha512":       true,
}

// certificatesAt returns the service provider's certificates usable at now.
// An entry that cannot be parsed is an error (fail closed): a broken
// configuration must not silently turn signature checks off.
func certificatesAt(app *domain.ClientApp, now time.Time) ([]*x509.Certificate, error) {
	entries, err := app.Certificates()
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for i, e := range entries {
		block, _ := pem.Decode([]byte(e.PEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("client_certificates[%d]: not a PEM certificate", i)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("client_certificates[%d]: %w", i, err)
		}
		if !e.ActiveAt(now) || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		out = append(out, cert)
	}
	return out, nil
}

// hasCertificates reports whether any certificate is configured at all,
// usable now or not. A provider whose certificates all expired must not
// fall back to "unsigned is fine".
func hasCertificates(app *domain.ClientApp) bool { return len(app.ClientCertificates) > 0 }

// parseXML reads a SAML message. The round-trip validator refuses XML that
// Go's encoding/xml would read differently from what it says (the class of
// bugs behind several SAML signature bypasses); encoding/xml itself never
// resolves external entities (no XXE).
func parseXML(b []byte) (*etree.Document, error) {
	if err := xrv.Validate(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadMessage, err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		return nil, fmt.Errorf("%w: %v", errBadMessage, err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("%w: empty document", errBadMessage)
	}
	return doc, nil
}

// verifyInbound checks the signature of a message from a service provider.
// It returns the root element to read the message from: for an XML
// signature, the element goxmldsig verified (built from the signed bytes
// only), so nothing unsigned can be smuggled next to the signed content.
//
// required: the provider must sign (it has certificates). With no
// certificate usable, a signature cannot be checked and is ignored.
func (a *Adapter) verifyInbound(in *inbound, root *etree.Element, app *domain.ClientApp) (*etree.Element, error) {
	now := a.now()
	certs, err := certificatesAt(app, now)
	if err != nil {
		return nil, err
	}
	if !hasCertificates(app) {
		return root, nil
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificate of %s is valid now", errBadSignature, app.EntityID)
	}

	switch {
	case in.Binding == bindingRedirect && in.SigAlg != "":
		if err := verifyQuerySignature(in, certs); err != nil {
			return nil, err
		}
		return root, nil
	case in.Binding == bindingRedirect:
		return nil, errUnsigned
	default: // HTTP-POST: enveloped XML signature
		return a.verifyXMLSignature(root, certs, now)
	}
}

func verifyQuerySignature(in *inbound, certs []*x509.Certificate) error {
	hash, ok := signatureHashes[in.SigAlg]
	if !ok {
		return errWeakAlgo
	}
	h := hash.New()
	h.Write([]byte(in.SignedPart))
	digest := h.Sum(nil)
	for _, cert := range certs {
		if verifyDigest(cert.PublicKey, hash, digest, in.Signature) {
			return nil
		}
	}
	return errBadSignature
}

func verifyDigest(pub crypto.PublicKey, hash crypto.Hash, digest, sig []byte) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, digest, sig) == nil
	case *ecdsa.PublicKey:
		// XML-DSig ECDSA values are r||s (RFC 4050); some senders use DER.
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) == 2*size {
			r := new(big.Int).SetBytes(sig[:size])
			s := new(big.Int).SetBytes(sig[size:])
			if ecdsa.Verify(k, digest, r, s) {
				return true
			}
		}
		var der struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(sig, &der); err == nil && len(rest) == 0 && der.R != nil && der.S != nil {
			return ecdsa.Verify(k, digest, der.R, der.S)
		}
	}
	return false
}

func (a *Adapter) verifyXMLSignature(root *etree.Element, certs []*x509.Certificate, now time.Time) (*etree.Element, error) {
	sig := childNS(root, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if sig == nil {
		return nil, errUnsigned
	}
	if err := checkSignatureAlgorithms(sig); err != nil {
		return nil, err
	}
	var lastErr error
	for _, cert := range certs {
		vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		vctx.IdAttribute = "ID"
		vctx.Clock = dsig.NewFakeClockAt(now)
		el := root.Copy()
		// A <KeyInfo> without a certificate (a bare RSAKeyValue) proves
		// nothing: drop it so that the configured certificate is used.
		if s := childNS(el, "http://www.w3.org/2000/09/xmldsig#", "Signature"); s != nil {
			if ki := s.FindElement("./KeyInfo"); ki != nil && ki.FindElement("./X509Data/X509Certificate") == nil {
				s.RemoveChild(ki)
			}
		}
		verified, err := vctx.Validate(el)
		if err == nil {
			return verified, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w: %v", errBadSignature, lastErr)
}

func checkSignatureAlgorithms(sig *etree.Element) error {
	sm := sig.FindElement("./SignedInfo/SignatureMethod")
	if sm == nil {
		return errBadSignature
	}
	if _, ok := signatureHashes[sm.SelectAttrValue("Algorithm", "")]; !ok {
		return errWeakAlgo
	}
	refs := sig.FindElements("./SignedInfo/Reference")
	if len(refs) != 1 {
		return fmt.Errorf("%w: exactly one Reference expected", errBadSignature)
	}
	dm := refs[0].FindElement("./DigestMethod")
	if dm == nil || !digestAlgorithms[dm.SelectAttrValue("Algorithm", "")] {
		return errWeakAlgo
	}
	return nil
}

// childNS returns the first direct child of el with that namespace URI and
// local name, whatever prefix the sender chose.
func childNS(el *etree.Element, ns, local string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == local && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

// isProtocolElement reports whether el is <samlp:local> in the SAML
// protocol namespace, whatever its prefix.
func isProtocolElement(el *etree.Element, local string) bool {
	return el != nil && el.Tag == local && strings.EqualFold(el.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:protocol")
}
