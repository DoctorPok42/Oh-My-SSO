package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestValkeyOptions(t *testing.T) {
	o, err := valkeyOptionsFrom(env(map[string]string{"VALKEY_ADDR": "localhost:6379"}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.Addresses, []string{"localhost:6379"}) || o.Password != "" || o.TLS != nil || o.DB != 0 {
		t.Fatalf("development defaults: %+v", o)
	}
	if got := describeValkey(o); got != "localhost:6379, no password, no TLS" {
		t.Errorf("describe = %q", got)
	}

	o, err = valkeyOptionsFrom(env(map[string]string{
		"APP_ENV":                  "production",
		"VALKEY_ADDR":              " s1:26379, s2:26379 ,",
		"VALKEY_USERNAME":          "sso",
		"VALKEY_PASSWORD":          "secret",
		"VALKEY_TLS":               "true",
		"VALKEY_SENTINEL_MASTER":   "mymaster",
		"VALKEY_SENTINEL_PASSWORD": "sentinel-secret",
		"VALKEY_DB":                "3",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.Addresses, []string{"s1:26379", "s2:26379"}) || o.Username != "sso" || o.Password != "secret" ||
		o.SentinelMaster != "mymaster" || o.SentinelPassword != "sentinel-secret" || o.DB != 3 {
		t.Fatalf("every setting: %+v", o)
	}
	if o.TLS == nil || o.TLS.RootCAs != nil {
		t.Fatalf("VALKEY_TLS without a CA file: the system's CAs, got %+v", o.TLS)
	}
	desc := describeValkey(o)
	if strings.Contains(desc, "secret") {
		t.Fatalf("the log line shows a secret: %q", desc)
	}
	if desc != "s1:26379,s2:26379 (sentinels of mymaster), db 3, user sso, TLS" {
		t.Errorf("describe = %q", desc)
	}
}

func TestValkeyOptionsCAFile(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := valkeyOptionsFrom(env(map[string]string{
		"VALKEY_ADDR": "valkey:6380", "VALKEY_TLS": "1", "VALKEY_TLS_CA_FILE": caFile,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if o.TLS == nil || o.TLS.RootCAs == nil {
		t.Fatal("the CA file must replace the system's CAs")
	}

	notPEM := filepath.Join(dir, "x.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"missing": filepath.Join(dir, "none.pem"), "not PEM": notPEM} {
		if _, err := valkeyOptionsFrom(env(map[string]string{
			"VALKEY_ADDR": "valkey:6380", "VALKEY_TLS": "true", "VALKEY_TLS_CA_FILE": file,
		})); err == nil {
			t.Errorf("%s CA file: no error", name)
		}
	}
}

func TestValkeyOptionsRefused(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"no address":          {},
		"blank addresses":     {"VALKEY_ADDR": " , "},
		"no port":             {"VALKEY_ADDR": "valkey"},
		"bad port":            {"VALKEY_ADDR": "valkey:http"},
		"port out of range":   {"VALKEY_ADDR": "valkey:70000"},
		"no host":             {"VALKEY_ADDR": ":6379"},
		"a scheme":            {"VALKEY_ADDR": "redis://valkey:6379"},
		"credentials":         {"VALKEY_ADDR": "user@valkey:6379"},
		"production, no pw":   {"VALKEY_ADDR": "valkey:6379", "APP_ENV": "production"},
		"user without pw":     {"VALKEY_ADDR": "valkey:6379", "VALKEY_USERNAME": "sso"},
		"TLS not a boolean":   {"VALKEY_ADDR": "valkey:6379", "VALKEY_TLS": "yes please"},
		"CA file without TLS": {"VALKEY_ADDR": "valkey:6379", "VALKEY_TLS_CA_FILE": "/certs/ca.pem"},
		"sentinel pw alone":   {"VALKEY_ADDR": "valkey:6379", "VALKEY_SENTINEL_PASSWORD": "x"},
		"negative db":         {"VALKEY_ADDR": "valkey:6379", "VALKEY_DB": "-1"},
		"db not a number":     {"VALKEY_ADDR": "valkey:6379", "VALKEY_DB": "one"},
	} {
		if o, err := valkeyOptionsFrom(env(vars)); err == nil {
			t.Errorf("%s: accepted, %+v", name, o)
		}
	}
	// Development may run without a password.
	if _, err := valkeyOptionsFrom(env(map[string]string{"VALKEY_ADDR": "valkey:6379", "APP_ENV": "development"})); err != nil {
		t.Errorf("development without a password: %v", err)
	}
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
