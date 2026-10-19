package vault_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"sso.internal/sso/internal/keymanager/vault"
)

// fakeTransit mimics the three Transit endpoints used for envelope
// encryption, enough to check the requests we send and how we read the
// answers. The real thing is covered by TestVaultIntegration_EncryptDecrypt.
type fakeTransit struct {
	mu       sync.Mutex
	keys     map[string]string // name -> type
	lastSign map[string]any    // body of the last /sign request (Step 11)
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/transit/"), "/")
	if r.Header.Get("X-Vault-Token") != "test-token" || len(parts) != 2 || r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, `{"errors":["denied"]}`, http.StatusForbidden)
		return
	}
	op, name := parts[0], parts[1]
	reply := func(data map[string]any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
	switch op {
	case "keys":
		f.keys[name], _ = body["type"].(string)
		w.WriteHeader(http.StatusNoContent)
	case "encrypt":
		if f.keys[name] != "aes256-gcm96" {
			http.Error(w, `{"errors":["no such key"]}`, http.StatusBadRequest)
			return
		}
		pt, _ := body["plaintext"].(string)
		reply(map[string]any{"ciphertext": "vault:v1:" + name + ":" + pt}) // not real crypto, just reversible
	case "decrypt":
		ct, _ := body["ciphertext"].(string)
		prefix := "vault:v1:" + name + ":"
		if !strings.HasPrefix(ct, prefix) {
			http.Error(w, `{"errors":["cipher: message authentication failed"]}`, http.StatusBadRequest)
			return
		}
		reply(map[string]any{"plaintext": strings.TrimPrefix(ct, prefix)})
	case "sign":
		// Step 11: remember the request, answer a recognizable signature.
		f.lastSign = body
		reply(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString([]byte("sig-of-"+name))})
	default:
		http.Error(w, `{"errors":["unsupported"]}`, http.StatusNotFound)
	}
}

func TestVault_EncryptDecrypt_Requests(t *testing.T) {
	ft := &fakeTransit{keys: map[string]string{}}
	srv := httptest.NewServer(ft)
	defer srv.Close()

	km, err := vault.New(vault.Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	ref, err := km.GenerateEncryptionKey(ctx)
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	if ft.keys[ref] != "aes256-gcm96" {
		t.Fatalf("key created with type %q, want aes256-gcm96", ft.keys[ref])
	}

	ct, err := km.Encrypt(ctx, ref, []byte("data key"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(string(ct), "vault:v1:") || !strings.HasSuffix(string(ct), base64.StdEncoding.EncodeToString([]byte("data key"))) {
		t.Fatalf("unexpected ciphertext %q (plaintext must be sent base64-encoded)", ct)
	}

	pt, err := km.Decrypt(ctx, ref, ct)
	if err != nil || string(pt) != "data key" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}

	if _, err := km.Decrypt(ctx, "other-key", ct); err == nil {
		t.Fatal("decrypt with the wrong key must fail")
	}
}

// Step 11: SignDigest asks Transit to sign our digest as it is ("prehashed").
func TestVault_SignDigest_Request(t *testing.T) {
	ft := &fakeTransit{keys: map[string]string{}}
	srv := httptest.NewServer(ft)
	defer srv.Close()
	km, err := vault.New(vault.Config{Address: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("payload"))
	sig, err := km.SignDigest(context.Background(), "saml-key", digest[:])
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if string(sig) != "sig-of-saml-key" {
		t.Fatalf("signature %q", sig)
	}
	want := map[string]any{
		"input": base64.StdEncoding.EncodeToString(digest[:]), "prehashed": true,
		"hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15",
	}
	for k, v := range want {
		if ft.lastSign[k] != v {
			t.Fatalf("request field %s = %v, want %v", k, ft.lastSign[k], v)
		}
	}
	if _, err := km.SignDigest(context.Background(), "saml-key", []byte("short")); err == nil {
		t.Fatal("a digest that is not SHA-256 sized must be refused")
	}
}
