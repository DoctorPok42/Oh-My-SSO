package service_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// testCertificate returns a self-signed certificate, PEM and DER.
func testCertificate(t *testing.T, key any, pub any) (string, []byte) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}

func ecCertificate(t *testing.T) (string, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return testCertificate(t, k, &k.PublicKey)
}

func TestNormalizeSAMLClient(t *testing.T) {
	certPEM, certDER := ecCertificate(t)
	base := func(mod func(*service.SAMLClientInput)) service.SAMLClientInput {
		in := service.SAMLClientInput{
			EntityID: "https://sp.example.com/metadata",
			ACSURL:   "https://sp.example.com/acs",
		}
		if mod != nil {
			mod(&in)
		}
		return in
	}

	t.Run("defaults", func(t *testing.T) {
		got, err := service.NormalizeSAMLClient(base(nil))
		require.NoError(t, err)
		require.Equal(t, "https://sp.example.com/metadata", got.Name, "the name defaults to the entity ID")
		require.Equal(t, domain.NameIDFormatPersistent, got.NameIDFormat)
		require.Empty(t, got.SLOURL)
		require.Empty(t, got.Certificates)
	})

	t.Run("short NameID names, certificates in both forms, deduplicated", func(t *testing.T) {
		got, err := service.NormalizeSAMLClient(base(func(in *service.SAMLClientInput) {
			in.NameIDFormat = "email"
			in.SLOURL = "http://localhost:8081/slo"
			in.Certificates = []domain.ClientCertificate{
				{PEM: certPEM},
				{PEM: base64.StdEncoding.EncodeToString(certDER)}, // as found in SAML metadata
			}
			in.AttributeMappings = map[string]string{"mail": "email"}
		}))
		require.NoError(t, err)
		require.Equal(t, domain.NameIDFormatEmail, got.NameIDFormat)
		require.Len(t, got.Certificates, 1, "the same certificate twice is kept once")
		require.True(t, strings.HasPrefix(got.Certificates[0].PEM, "-----BEGIN CERTIFICATE-----"))
		require.Equal(t, map[string]interface{}{"mail": "email"}, got.AttributeMappings)
	})

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPEM, _ := testCertificate(t, edKey, edKey.Public())

	refused := map[string]func(*service.SAMLClientInput){
		"no entity ID":                    func(in *service.SAMLClientInput) { in.EntityID = " " },
		"entity ID with a space":          func(in *service.SAMLClientInput) { in.EntityID = "my sp" },
		"entity ID too long":              func(in *service.SAMLClientInput) { in.EntityID = strings.Repeat("a", 1025) },
		"no ACS":                          func(in *service.SAMLClientInput) { in.ACSURL = "" },
		"relative ACS":                    func(in *service.SAMLClientInput) { in.ACSURL = "/acs" },
		"javascript ACS (CVE-2023-45683)": func(in *service.SAMLClientInput) { in.ACSURL = "javascript:alert(1)" },
		"http ACS on a real host":         func(in *service.SAMLClientInput) { in.ACSURL = "http://sp.example.com/acs" },
		"ACS with a fragment":             func(in *service.SAMLClientInput) { in.ACSURL = "https://sp.example.com/acs#x" },
		"ACS with user info":              func(in *service.SAMLClientInput) { in.ACSURL = "https://u:p@sp.example.com/acs" },
		"bad SLO":                         func(in *service.SAMLClientInput) { in.SLOURL = "ftp://sp.example.com/slo" },
		"unknown NameID format":           func(in *service.SAMLClientInput) { in.NameIDFormat = "kerberos" },
		"pairwise with email NameIDs":     func(in *service.SAMLClientInput) { in.Pairwise = true; in.NameIDFormat = "email" },
		"not a certificate":               func(in *service.SAMLClientInput) { in.Certificates = []domain.ClientCertificate{{PEM: "hello"}} },
		"Ed25519 certificate":             func(in *service.SAMLClientInput) { in.Certificates = []domain.ClientCertificate{{PEM: edPEM}} },
		"window upside down": func(in *service.SAMLClientInput) {
			in.Certificates = []domain.ClientCertificate{{PEM: certPEM,
				NotBefore: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}
		},
		"empty rename": func(in *service.SAMLClientInput) { in.AttributeMappings = map[string]string{"mail": ""} },
	}
	for name, mod := range refused {
		t.Run("refused: "+name, func(t *testing.T) {
			_, err := service.NormalizeSAMLClient(base(mod))
			require.ErrorIs(t, err, service.ErrInvalidClientConfig)
		})
	}
}

func TestClientCertificates(t *testing.T) {
	certPEM, certDER := ecCertificate(t)
	fp, err := service.CertificateFingerprint(certPEM)
	require.NoError(t, err)
	fp2, err := service.CertificateFingerprint(base64.StdEncoding.EncodeToString(certDER))
	require.NoError(t, err)
	require.Equal(t, fp, fp2)
	require.Len(t, fp, 64)

	jan := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	feb := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	app := &domain.ClientApp{ClientCertificates: []map[string]interface{}{
		domain.ClientCertificate{PEM: certPEM}.ToMap(),
		domain.ClientCertificate{PEM: certPEM, NotBefore: jan, NotAfter: feb}.ToMap(),
	}}
	certs, err := app.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 2)
	require.True(t, certs[0].ActiveAt(jan.Add(-time.Hour)), "no window: always")
	require.False(t, certs[1].ActiveAt(jan.Add(-time.Second)))
	require.True(t, certs[1].ActiveAt(jan))
	require.False(t, certs[1].ActiveAt(feb), "not_after is exclusive")

	app.ClientCertificates = []map[string]interface{}{{"certificate": certPEM, "not_after": "next tuesday"}}
	_, err = app.Certificates()
	require.Error(t, err, "a bad date is an error, never a wider window")
}
