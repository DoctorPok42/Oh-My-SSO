package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // only to prove SHA-1 signatures are refused
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samllib "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// spKey is a service provider's key pair with its certificate.
type spKey struct {
	key  crypto.Signer
	cert *x509.Certificate
	pem  string
}

func newSPKey(t *testing.T, ec bool, notBefore, notAfter time.Time) *spKey {
	t.Helper()
	var key crypto.Signer
	var err error
	if ec {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &spKey{key: key, cert: cert, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func validSPKey(t *testing.T, ec bool) *spKey {
	return newSPKey(t, ec, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func appWith(keys ...*spKey) *domain.ClientApp {
	app := &domain.ClientApp{EntityID: "https://sp.example.test/metadata", ClientCertificates: []map[string]interface{}{}}
	for _, k := range keys {
		app.ClientCertificates = append(app.ClientCertificates, domain.ClientCertificate{PEM: k.pem}.ToMap())
	}
	return app
}

func testAdapter() *Adapter {
	return &Adapter{logger: quiet, now: time.Now}
}


func deflateB64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, _ = w.Write([]byte(s))
	require.NoError(t, w.Close())
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// signQuery signs a redirect query like a service provider would.
func signQuery(t *testing.T, k *spKey, alg string, q string, rawSig bool) string {
	t.Helper()
	q += "&SigAlg=" + url.QueryEscape(alg)
	var hash crypto.Hash
	var digest []byte
	switch alg {
	case dsig.RSASHA1SignatureMethod:
		hash = crypto.SHA1
		d := sha1.Sum([]byte(q)) //nolint:gosec
		digest = d[:]
	default:
		hash = crypto.SHA256
		d := sha256.Sum256([]byte(q))
		digest = d[:]
	}
	sig, err := k.key.Sign(rand.Reader, digest, hash)
	require.NoError(t, err)
	if ek, ok := k.key.(*ecdsa.PrivateKey); ok && rawSig {
		r, s, err := ecdsa.Sign(rand.Reader, ek, digest)
		require.NoError(t, err)
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func TestReadRedirect(t *testing.T) {
	msg := deflateB64(t, "<samlp:AuthnRequest/>")

	t.Run("signed part keeps the raw encoding", func(t *testing.T) {
		q := "SAMLRequest=" + url.QueryEscape(msg) + "&RelayState=" + url.QueryEscape("https://app/x?y=1 2")
		k := validSPKey(t, false)
		raw := signQuery(t, k, dsig.RSASHA256SignatureMethod, q, false)
		in, err := readRedirect(raw+"&extra=ignored", []string{paramRequest})
		require.NoError(t, err)
		require.Equal(t, "<samlp:AuthnRequest/>", string(in.XML))
		require.Equal(t, "https://app/x?y=1 2", in.RelayState)
		require.Equal(t, dsig.RSASHA256SignatureMethod, in.SigAlg)
		require.Equal(t, q+"&SigAlg="+url.QueryEscape(dsig.RSASHA256SignatureMethod), in.SignedPart)
		require.NoError(t, verifyQuerySignature(in, []*x509.Certificate{k.cert}))
	})

	refused := map[string]string{
		"no message":               "RelayState=x",
		"repeated message":         "SAMLRequest=" + url.QueryEscape(msg) + "&SAMLRequest=" + url.QueryEscape(msg),
		"SigAlg without Signature": "SAMLRequest=" + url.QueryEscape(msg) + "&SigAlg=x",
		"not base64":               "SAMLRequest=%%%",
		"not deflate":              "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("plain"))),
		"RelayState too long":      "SAMLRequest=" + url.QueryEscape(msg) + "&RelayState=" + strings.Repeat("a", maxRelayState+1),
	}
	for name, q := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			_, err := readRedirect(q, []string{paramRequest})
			require.Error(t, err)
		})
	}

	t.Run("a DEFLATE bomb is cut", func(t *testing.T) {
		bomb := deflateB64(t, strings.Repeat("A", maxXMLMessage+10))
		require.Less(t, len(bomb), 2000, "tiny on the wire")
		_, err := readRedirect("SAMLRequest="+url.QueryEscape(bomb), []string{paramRequest})
		require.ErrorContains(t, err, "too large")
	})
}

func TestVerifyQuerySignature(t *testing.T) {
	q := "SAMLRequest=" + url.QueryEscape(deflateB64(t, "<x/>"))
	rsaKey, ecKey, other := validSPKey(t, false), validSPKey(t, true), validSPKey(t, false)

	check := func(raw string, certs ...*spKey) error {
		in, err := readRedirect(raw, []string{paramRequest})
		require.NoError(t, err)
		var cs []*x509.Certificate
		for _, c := range certs {
			cs = append(cs, c.cert)
		}
		return verifyQuerySignature(in, cs)
	}
	require.NoError(t, check(signQuery(t, rsaKey, dsig.RSASHA256SignatureMethod, q, false), rsaKey))
	require.NoError(t, check(signQuery(t, ecKey, dsig.ECDSASHA256SignatureMethod, q, false), ecKey), "ECDSA, DER")
	require.NoError(t, check(signQuery(t, ecKey, dsig.ECDSASHA256SignatureMethod, q, true), ecKey), "ECDSA, r||s")
	require.NoError(t, check(signQuery(t, rsaKey, dsig.RSASHA256SignatureMethod, q, false), other, rsaKey),
		"rotation: any configured certificate")
	require.ErrorIs(t, check(signQuery(t, rsaKey, dsig.RSASHA256SignatureMethod, q, false), other), errBadSignature)
	require.ErrorIs(t, check(signQuery(t, rsaKey, dsig.RSASHA1SignatureMethod, q, false), rsaKey), errWeakAlgo)

	signed := signQuery(t, rsaKey, dsig.RSASHA256SignatureMethod, q, false)
	tampered := strings.Replace(signed, "SAMLRequest=", "RelayState=evil&SAMLRequest=", 1)
	require.ErrorIs(t, check(tampered, rsaKey), errBadSignature, "an added parameter breaks the signature")
}


func TestCertificatesAt(t *testing.T) {
	now := time.Now()
	current := validSPKey(t, false)
	expired := newSPKey(t, false, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	next := validSPKey(t, false)

	app := appWith(current, expired)
	app.ClientCertificates = append(app.ClientCertificates, domain.ClientCertificate{PEM: next.pem, NotBefore: now.Add(time.Hour)}.ToMap())
	certs, err := certificatesAt(app, now)
	require.NoError(t, err)
	require.Len(t, certs, 1, "expired X.509 and not-yet-active window are skipped")
	require.True(t, certs[0].Equal(current.cert))

	certs, err = certificatesAt(app, now.Add(90*time.Minute))
	require.NoError(t, err)
	require.Len(t, certs, 0, "the X.509 dates of both are over by then")

	app.ClientCertificates = append(app.ClientCertificates, map[string]interface{}{"certificate": "garbage"})
	_, err = certificatesAt(app, now)
	require.Error(t, err, "a broken entry never turns checks off")
}

// signedAuthnRequest builds an AuthnRequest signed by sp (XML-DSig, POST binding).
func signedAuthnRequest(t *testing.T, k *spKey, alg string, id string) []byte {
	t.Helper()
	sp := &samllib.ServiceProvider{Key: k.key, Certificate: k.cert, SignatureMethod: alg, EntityID: "https://sp.example.test/metadata"}
	req := samllib.AuthnRequest{ID: id, Version: "2.0", IssueInstant: time.Now().UTC(),
		Destination: "https://idp.example.test/r/acme/saml/sso",
		Issuer:      &samllib.Issuer{Value: sp.EntityID}, AssertionConsumerServiceURL: "https://sp.example.test/acs"}
	require.NoError(t, sp.SignAuthnRequest(&req))
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	b, err := doc.WriteToBytes()
	require.NoError(t, err)
	return b
}

func TestVerifyXMLSignature(t *testing.T) {
	a := testAdapter()
	k, other := validSPKey(t, false), validSPKey(t, false)

	verify := func(xmlMsg []byte, app *domain.ClientApp) (*etree.Element, error) {
		doc, err := parseXML(xmlMsg)
		require.NoError(t, err)
		return a.verifyInbound(&inbound{Binding: bindingPOST, XML: xmlMsg}, doc.Root(), app)
	}

	msg := signedAuthnRequest(t, k, dsig.RSASHA256SignatureMethod, "_req1")
	el, err := verify(msg, appWith(k))
	require.NoError(t, err)
	require.Equal(t, "_req1", el.SelectAttrValue("ID", ""))

	_, err = verify(msg, appWith(other, k))
	require.NoError(t, err, "rotation: the second certificate verifies")

	_, err = verify(msg, appWith(other))
	require.ErrorIs(t, err, errBadSignature)

	tampered := bytes.Replace(msg, []byte("https://sp.example.test/acs"), []byte("https://evil.example/acs"), 1)
	_, err = verify(tampered, appWith(k))
	require.ErrorIs(t, err, errBadSignature, "a signed field changed")

	sha1Msg := signedAuthnRequest(t, k, dsig.RSASHA1SignatureMethod, "_req2")
	_, err = verify(sha1Msg, appWith(k))
	require.ErrorIs(t, err, errWeakAlgo)

	unsigned := []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>`)
	_, err = verify(unsigned, appWith(k))
	require.ErrorIs(t, err, errUnsigned, "a provider with a certificate must sign")
	el, err = verify(unsigned, appWith())
	require.NoError(t, err, "without certificate, no signature is required")
	require.Equal(t, "_x", el.SelectAttrValue("ID", ""))

	t.Run("signature wrapping: the verified element is what gets read", func(t *testing.T) {
		// An attacker moves the signed request inside a new root with
		// other values. The signature references "_req1", not the root.
		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(msg))
		signedEl := doc.Root()
		evil := etree.NewElement("samlp:AuthnRequest")
		evil.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
		evil.CreateAttr("ID", "_evil")
		evil.AddChild(signedEl.FindElement("./Signature").Copy())
		ext := evil.CreateElement("samlp:Extensions")
		ext.AddChild(signedEl.Copy())
		wrapped := etree.NewDocument()
		wrapped.SetRoot(evil)
		b, _ := wrapped.WriteToBytes()
		_, err := verify(b, appWith(k))
		require.Error(t, err)
	})
}


func TestBuildAttributes(t *testing.T) {
	as := &core.IdentityAssertion{
		UserAttributes: map[string]any{
			"username": "alice", "email": "alice@example.test", "groups": []string{"admins", "devs"},
			"profile.given_name": "Alice", "updated_at": int64(42), "roles": []string{},
		},
		Scopes: []*domain.ClientScope{
			{Name: "saml_profile", Protocol: domain.ClientScopeProtocolSAML2, ClaimMappers: []map[string]interface{}{
				{"source_attribute": "username", "claim_name": "uid"}, // saml2 scope: SAML by default
				{"source_attribute": "email", "claim_name": "mail", "saml_name_format": "uri", "saml_friendly_name": "mail"},
				{"source_attribute": "groups", "claim_name": "memberOf"},
				{"source_attribute": "roles", "claim_name": "roles"},                                                // empty: no attribute
				{"source_attribute": "profile.given_name", "claim_name": "givenName", "token_location": "id_token"}, // not SAML
			}},
			{Name: "both", Protocol: domain.ClientScopeProtocolBoth, ClaimMappers: []map[string]interface{}{
				{"source_attribute": "updated_at", "claim_name": "updated"}, // "both": must say saml_attribute
				{"source_attribute": "profile.given_name", "claim_name": "givenName", "token_location": []interface{}{"id_token", "saml_attribute"}},
				{"source_attribute": "groups", "claim_name": "memberOf", "token_location": "saml_attribute"}, // merged
			}},
			{Name: "oidc only", Protocol: domain.ClientScopeProtocolOIDC, ClaimMappers: []map[string]interface{}{
				{"source_attribute": "email", "claim_name": "leak", "token_location": "saml_attribute"},
			}},
		},
	}
	app := &domain.ClientApp{EntityID: "sp", AttributeMappings: map[string]interface{}{"uid": "user", "mail": "givenName"}}
	attrs := buildAttributes(as, app, quiet)

	got := map[string][]string{}
	for _, at := range attrs {
		for _, v := range at.Values {
			got[at.Name] = append(got[at.Name], v.Value)
		}
	}
	require.Equal(t, map[string][]string{
		"user":      {"alice"},              // renamed uid -> user
		"mail":      {"alice@example.test"}, // rename to givenName skipped: taken
		"memberOf":  {"admins", "devs"},     // multi-valued, merged without duplicates
		"givenName": {"Alice"},
	}, got)
	for _, at := range attrs {
		if at.Name == "mail" {
			require.Equal(t, attrNameFormatURI, at.NameFormat)
			require.Equal(t, "mail", at.FriendlyName)
		} else {
			require.Equal(t, attrNameFormatBasic, at.NameFormat)
		}
	}
}

func TestNameIDValue(t *testing.T) {
	as := &core.IdentityAssertion{Subject: "sub-123", UserAttributes: map[string]any{"email": "a@example.test"}}
	for format, want := range map[string]string{
		domain.NameIDFormatPersistent:  "sub-123",
		domain.NameIDFormatUnspecified: "sub-123",
		domain.NameIDFormatEmail:       "a@example.test",
	} {
		got, err := nameIDValue(format, as)
		require.NoError(t, err)
		require.Equal(t, want, got, format)
	}
	t1, _ := nameIDValue(domain.NameIDFormatTransient, as)
	t2, _ := nameIDValue(domain.NameIDFormatTransient, as)
	require.NotEqual(t, t1, t2, "transient: random")
	require.True(t, strings.HasPrefix(t1, "_"))

	_, err := nameIDValue(domain.NameIDFormatEmail, &core.IdentityAssertion{UserAttributes: map[string]any{}})
	require.ErrorIs(t, err, errNoEmail)
}


func TestParseSPMetadata(t *testing.T) {
	k := validSPKey(t, false)
	enc := validSPKey(t, false)
	certB64 := func(s *spKey) string { return base64.StdEncoding.EncodeToString(s.cert.Raw) }
	xmlMD := `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:8081/module.php/saml/sp/metadata/default-sp">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
` + certB64(k) + `
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certB64(enc) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://localhost:8081/soap"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8081/module.php/saml/sp/singleLogoutService/default-sp"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="http://localhost:8081/saml1" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8081/module.php/saml/sp/saml2-acs.php/default-sp" index="0"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://localhost:8081/artifact" index="2"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`
	md, err := ParseSPMetadata([]byte(xmlMD))
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8081/module.php/saml/sp/metadata/default-sp", md.EntityID)
	require.Equal(t, "http://localhost:8081/module.php/saml/sp/saml2-acs.php/default-sp", md.ACSURL)
	require.Equal(t, "http://localhost:8081/module.php/saml/sp/singleLogoutService/default-sp", md.SLOURL)
	require.Equal(t, []string{certB64(k)}, md.Certificates, "signing certificate only, whitespace removed")
	require.Equal(t, domain.NameIDFormatTransient, md.NameIDFormat)
	require.True(t, md.AuthnRequestsSigned)
	require.Len(t, md.Warnings, 2, "the two non HTTP-POST ACS endpoints")

	_, err = ParseSPMetadata([]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>`))
	require.ErrorContains(t, err, "no SPSSODescriptor")
	_, err = ParseSPMetadata([]byte(`not xml`))
	require.Error(t, err)
}
