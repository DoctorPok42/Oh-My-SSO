package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/core/domain"
)

func TestWebAuthnResult(t *testing.T) {
	for _, c := range []struct {
		name, rpID, origins, publicURL, appEnv, want, detail string
	}{
		{"all right", "sso.example.com", "https://sso.example.com", "https://sso.example.com", "production", "OK", "RP ID sso.example.com"},
		{"parent domain", "example.com", "https://sso.example.com", "https://sso.example.com/", "production", "OK", ""},
		{"dev on localhost", "localhost", "http://localhost:8080", "http://localhost:8080", "development", "OK", ""},
		{"no RP ID", "", "", "https://sso.example.com", "production", "FAIL", "cannot sign in"},
		{"no origin", "sso.example.com", "", "https://sso.example.com", "production", "FAIL", "WEBAUTHN_RP_ORIGINS"},
		{"origin without scheme", "sso.example.com", "sso.example.com", "https://sso.example.com", "production", "FAIL", "scheme://host"},
		{"plain http in production", "sso.example.com", "http://sso.example.com", "http://sso.example.com", "production", "FAIL", "plain http"},
		{"RP ID of another site", "other.test", "https://sso.example.com", "https://sso.example.com", "production", "FAIL", "neither the host"},
		{"suffix without a dot", "ample.com", "https://sso.example.com", "https://sso.example.com", "production", "FAIL", "neither the host"},
		{"origin missing", "sso.example.com", "https://other.example.com", "https://sso.example.com", "production", "FAIL", "does not list https://sso.example.com"},
		{"port counts", "localhost", "http://localhost:8080", "http://localhost:9090", "development", "FAIL", "does not list"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var origins []string
			if c.origins != "" {
				origins = strings.Split(c.origins, ",")
			}
			got := webauthnResult(c.rpID, origins, c.publicURL, c.appEnv == "production")
			if got.status != c.want || !strings.Contains(got.detail, c.detail) {
				t.Fatalf("got %s %q, want %s containing %q", got.status, got.detail, c.want, c.detail)
			}
		})
	}
}

func TestAllowsPhishingResistant(t *testing.T) {
	for _, c := range []struct {
		methods []domain.MfaMethodType
		want    bool
	}{
		{nil, true}, // any method: master narrows it itself
		{[]domain.MfaMethodType{domain.MfaMethodPasskey}, true},
		{[]domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodWebAuthn}, true},
		{[]domain.MfaMethodType{domain.MfaMethodTOTP}, false},
		{[]domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodBackupCodes}, false},
	} {
		if got := allowsPhishingResistant(c.methods); got != c.want {
			t.Errorf("allowsPhishingResistant(%v) = %v, want %v", c.methods, got, c.want)
		}
	}
}

func TestPublicURL(t *testing.T) {
	// This deployment: its discovery announces its own address as issuer.
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/r/master/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"issuer":"http://%s/r/master"}`, r.Host)
	}))
	defer same.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"issuer":"https://sso.example.com/r/master"}`)
	}))
	defer other.Close()
	selfSigned := httptest.NewTLSServer(http.NotFoundHandler())
	defer selfSigned.Close()

	for _, c := range []struct{ appEnv, url, want, detail string }{
		{"development", same.URL + "/", "OK", "expected issuer"},
		{"development", same.URL + "/sub", "FAIL", "404"},
		{"development", other.URL, "FAIL", "another PUBLIC_URL"},
		{"development", selfSigned.URL, "FAIL", "certificate refused"},
		{"production", same.URL, "FAIL", "not https"},
		{"development", "ftp://sso.example.com", "FAIL", "not an http(s) URL"},
	} {
		t.Setenv("APP_ENV", c.appEnv)
		t.Setenv("PUBLIC_URL", c.url)
		got := (&doctor{}).publicURL(context.Background())
		if got.status != c.want || !strings.Contains(got.detail, c.detail) {
			t.Errorf("%s %s: %s (%s), want %s with %q", c.appEnv, c.url, got.status, got.detail, c.want, c.detail)
		}
	}
}

func TestKeyManagerDoesNotHang(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never answers: the AppRole sign-in waits
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("KEYMANAGER_BACKEND", "vault")
	t.Setenv("VAULT_ADDR", "http://"+ln.Addr().String())
	t.Setenv("VAULT_APPROLE_ROLE_ID", "role")
	t.Setenv("VAULT_APPROLE_SECRET_ID", "secret")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := (&doctor{}).keyManager(ctx)
	if got.status != "FAIL" || !strings.Contains(got.detail, "no answer") || time.Since(start) > 5*time.Second {
		t.Fatalf("%s (%s) after %s, want FAIL no answer at once", got.status, got.detail, time.Since(start))
	}
}

func TestSendingDomain(t *testing.T) {
	for from, want := range map[string]string{
		"SSO <no-reply@sso.example.com>": "sso.example.com",
		"Oh-My-SSO <no-reply@localhost>": "", // development: no DNS to read
		"":                               "", // no SMTP
	} {
		if got := (&doctor{from: from}).sendingDomain(); got != want {
			t.Errorf("%q: %q, want %q", from, got, want)
		}
	}
}

func TestClockResult(t *testing.T) {
	for drift, want := range map[time.Duration]string{
		2 * time.Second: "OK", -10 * time.Second: "WARN", 31 * time.Second: "FAIL", -31 * time.Second: "FAIL",
	} {
		if got := clockResult(drift); got.status != want {
			t.Errorf("drift %s: %s (%s), want %s", drift, got.status, got.detail, want)
		}
	}
}

func TestSPFResult(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	for _, c := range []struct {
		txt  []string
		err  error
		want string
	}{
		{[]string{"google-site-verification=x", "v=spf1 include:_spf.example.net -all"}, nil, "OK"},
		{[]string{"V=SPF1 -all"}, nil, "OK"},
		{[]string{"v=spf10 nope"}, nil, "WARN"},
		{nil, notFound, "WARN"},
		{[]string{"v=spf1 a -all", "v=spf1 mx -all"}, nil, "WARN"},
		{nil, errors.New("i/o timeout"), "WARN"},
	} {
		if got := spfResult("example.com", c.txt, c.err); got.status != c.want {
			t.Errorf("%q, %v: %s (%s), want %s", c.txt, c.err, got.status, got.detail, c.want)
		}
	}
}

func TestProxiesResult(t *testing.T) {
	for _, c := range []struct {
		raw   string
		https bool
		want  string
	}{
		{"", false, "OK"},
		{"", true, "WARN"},
		{"10.0.0.2", true, "OK"},
		{"10.0.0.2, 0.0.0.0/0", true, "FAIL"},
		{"::/0", false, "FAIL"},
	} {
		res, err := clientip.Parse(c.raw, "")
		if err != nil {
			t.Fatalf("%q: %v", c.raw, err)
		}
		if got := proxiesResult(c.raw, res, c.https); got.status != c.want {
			t.Errorf("%q, https=%v: %s (%s), want %s", c.raw, c.https, got.status, got.detail, c.want)
		}
	}
}
