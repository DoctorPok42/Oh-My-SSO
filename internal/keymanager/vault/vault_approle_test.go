package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeVault accepts AppRole logins and hands out short, non-renewable
// tokens; Transit sign only works with the latest token.
type fakeVault struct {
	mu      sync.Mutex
	current string
	logins  int32
	ns      string
	mount   string
	empty   bool
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/auth/approle/login":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != "role" || body["secret_id"] != "secret" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["denied"]}`))
			return
		}
		n := atomic.AddInt32(&f.logins, 1)
		f.current = "tok-" + strconv.Itoa(int(n))
		f.ns = r.Header.Get("X-Vault-Namespace")
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": f.current, "lease_duration": 1, "renewable": false,
		}})
	case "/v1/" + f.mount + "/sign/k":
		if f.empty {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("X-Vault-Token") != f.current {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v1:AAAA"}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestAppRoleRelogsAfterTokenExpiry(t *testing.T) {
	f := &fakeVault{mount: "mytransit"}
	srv := httptest.NewServer(f)
	defer srv.Close()

	km, err := New(Config{
		Address: srv.URL, MountPath: "mytransit", Namespace: "team",
		AppRoleID: "role", AppRoleSecretID: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()
	f.mu.Lock()
	ns := f.ns
	f.mu.Unlock()
	if ns != "team" {
		t.Fatalf("namespace header = %q", ns)
	}
	if _, err := km.Sign(context.Background(), "k", []byte("x")); err != nil {
		t.Fatalf("sign with first token: %v", err)
	}

	// The 1 s lease is up: a new login must have replaced the token.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&f.logins) < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt32(&f.logins) < 2 {
		t.Fatal("no new login after the token expired")
	}
	if _, err := km.Sign(context.Background(), "k", []byte("x")); err != nil {
		t.Fatalf("sign after re-login: %v", err)
	}
}

func TestAppRoleLoginFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(&fakeVault{mount: "transit"})
	defer srv.Close()
	if _, err := New(Config{Address: srv.URL, AppRoleID: "role", AppRoleSecretID: "bad"}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := New(Config{Address: srv.URL, AppRoleID: "role"}); err == nil {
		t.Fatal("expected an error without secret id")
	}
}

func TestSignEmptyResponseDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(&fakeVault{mount: "transit", empty: true})
	defer srv.Close()
	km, err := New(Config{Address: srv.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Sign(context.Background(), "k", []byte("x")); err == nil {
		t.Fatal("Sign: expected an error")
	}
	if _, err := km.SignDigest(context.Background(), "k", make([]byte, 32)); err == nil {
		t.Fatal("SignDigest: expected an error")
	}
}
