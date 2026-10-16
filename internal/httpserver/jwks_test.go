package httpserver_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/httpserver"
	"sso.internal/sso/internal/jwks"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/memstore"
)

// Step 8 - JWKS endpoint, tested through real HTTP requests on the router.

type jwksRealms struct {
	repository.RealmRepository // nil: any other method panics, on purpose
	byName                     map[string]*domain.Realm
}

func (f *jwksRealms) GetByName(_ context.Context, name string) (*domain.Realm, error) {
	if r, ok := f.byName[name]; ok {
		return r, nil
	}
	return nil, repository.ErrNotFound
}

type jwksNoSettings struct {
	repository.InstanceSettingsRepository
}

func (jwksNoSettings) GetByRealmID(context.Context, string) (*domain.InstanceSettings, error) {
	return nil, repository.ErrNotFound // -> 24h default grace
}

type jwksFixture struct {
	now    time.Time
	keys   *memstore.SigningKeys
	logs   *memstore.KeyRotationLogs
	rot    *service.KeyRotationService
	core   *service.IdentityCoreService
	server *httpserver.Server
	realm  *domain.Realm
}

func newJWKSFixture(t *testing.T) *jwksFixture {
	t.Helper()
	f := &jwksFixture{now: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }

	f.realm = &domain.Realm{ID: "realm-acme", Name: "acme", Status: domain.RealmActive}
	realms := &jwksRealms{byName: map[string]*domain.Realm{
		"acme":   f.realm,
		"closed": {ID: "realm-closed", Name: "closed", Status: domain.RealmInactive},
		"empty":  {ID: "realm-empty", Name: "empty", Status: domain.RealmActive},
	}}

	km := localdev.New("test")
	f.keys = memstore.NewSigningKeys(clock)
	f.logs = memstore.NewKeyRotationLogs(clock)
	f.rot = service.NewKeyRotationService(f.keys, f.logs, jwksNoSettings{}, km, "local_dev",
		service.WithKeyRotationClock(clock))
	f.core = service.NewIdentityCore(service.IdentityCoreDeps{SigningKeys: f.keys, KeyManager: km},
		service.WithIdentityCoreClock(clock))

	f.server = httpserver.New(nil, nil, nil, realms, nil, nil, httpserver.WithJWKS(f.core))
	return f
}

func (f *jwksFixture) rotate(t *testing.T) *domain.SigningKey {
	t.Helper()
	res, err := f.rot.Rotate(context.Background(), service.RotateInput{RealmID: f.realm.ID, TriggeredBy: "test"})
	require.NoError(t, err)
	f.now = f.now.Add(time.Second)
	return res.NewKey
}

func (f *jwksFixture) get(t *testing.T, path string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	f.server.Router().ServeHTTP(rec, req)
	return rec
}

// fetchJWKS is what a client does: download the JWK Set and parse it.
func (f *jwksFixture) fetchJWKS(t *testing.T) jwks.Set {
	t.Helper()
	rec := f.get(t, "/r/acme/.well-known/jwks.json", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var set jwks.Set
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &set))
	return set
}

// signJWT builds a real compact JWS (RFC 7515) "header.payload.signature"
// with the realm's current Signer - exactly what the OIDC adapter will do at
// Step 10. Only the KMS holds the private key: we just get a signature back.
func (f *jwksFixture) signJWT(t *testing.T, sub string) string {
	t.Helper()
	ctx := context.Background()
	signer, err := f.core.Signer(ctx, f.realm.ID, domain.SigningKeyPurposeJWT)
	require.NoError(t, err)
	alg, err := jwks.Algorithm(signer.KeyType())
	require.NoError(t, err)

	header, _ := json.Marshal(map[string]string{"alg": alg, "kid": signer.KeyID(), "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"sub": sub, "iat": f.now.Unix(), "exp": f.now.Add(time.Hour).Unix()})
	signingInput := b64(header) + "." + b64(payload)

	sig, err := signer.Sign(ctx, []byte(signingInput))
	require.NoError(t, err)
	return signingInput + "." + b64(sig)
}

// verifyJWT checks a token's signature the way a client does: read "kid"
// from the header, find that key in the JWKS, verify. Returns the reason on
// failure (a client would reject the token).
func verifyJWT(token string, set jwks.Set) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var header struct{ Alg, Kid string }
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return err
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("unexpected alg %q", header.Alg)
	}
	jwk, ok := set.Find(header.Kid)
	if !ok {
		return fmt.Errorf("unknown kid %q", header.Kid)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, digest[:], sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Definition of Done of Step 8: a token signed with the old key stays
// verifiable during the grace period, and stops being verifiable after it.
func TestJWKS_TokenSignedWithOldKeyVerifiesDuringGracePeriod(t *testing.T) {
	f := newJWKSFixture(t)
	oldKey := f.rotate(t)

	oldToken := f.signJWT(t, "alice")
	require.NoError(t, verifyJWT(oldToken, f.fetchJWKS(t)), "sanity check before any rotation")

	// --- rotation: default 24h grace ---
	newKey := f.rotate(t)
	rotatedAt := f.now

	set := f.fetchJWKS(t)
	require.Len(t, set.Keys, 2)
	require.Equal(t, newKey.Kid, set.Keys[0].Kid, "newest key first")
	require.NoError(t, verifyJWT(oldToken, set), "old token still verifies right after the rotation")

	newToken := f.signJWT(t, "bob")
	require.Equal(t, newKey.Kid, headerKid(t, newToken), "new tokens are signed with the new key")
	require.Equal(t, oldKey.Kid, headerKid(t, oldToken))
	require.NoError(t, verifyJWT(newToken, set))

	// --- 23h later: still inside the grace period ---
	f.now = rotatedAt.Add(23 * time.Hour)
	require.NoError(t, verifyJWT(oldToken, f.fetchJWKS(t)), "old token still verifies inside the grace period")

	// --- just after the deadline: the old key is gone from the JWKS, even
	// before anybody runs the retire job ---
	f.now = rotatedAt.Add(24*time.Hour + time.Second)
	set = f.fetchJWKS(t)
	require.Len(t, set.Keys, 1)
	require.ErrorContains(t, verifyJWT(oldToken, set), "unknown kid "+`"`+oldKey.Kid+`"`)
	require.NoError(t, verifyJWT(newToken, set), "tokens of the new key are unaffected")

	// --- the retire job tidies the status and writes the log ---
	retired, err := f.rot.RetireExpired(context.Background(), f.realm.ID, "test")
	require.NoError(t, err)
	require.Len(t, retired, 1)
	require.Equal(t, oldKey.Kid, retired[0].Kid)

	var got []domain.KeyRotationAction
	for _, l := range f.logs.All() {
		got = append(got, l.Action)
	}
	require.Equal(t, []domain.KeyRotationAction{
		domain.KeyRotationCreated, // old key
		domain.KeyRotationCreated, // new key
		domain.KeyRotationRotated, // old key -> rotating
		domain.KeyRotationRetired, // old key -> retired
	}, got)
}

func headerKid(t *testing.T, token string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)
	var h struct{ Kid string }
	require.NoError(t, json.Unmarshal(raw, &h))
	return h.Kid
}

func TestJWKS_HTTPHeadersAndConditionalRequests(t *testing.T) {
	f := newJWKSFixture(t)
	f.rotate(t)

	rec := f.get(t, "/r/acme/.well-known/jwks.json", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "public, max-age=300", rec.Header().Get("Cache-Control"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)

	// Same JWKS: 304 and no body.
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		rec = f.get(t, "/r/acme/.well-known/jwks.json", http.Header{"If-None-Match": {inm}})
		require.Equal(t, http.StatusNotModified, rec.Code, inm)
		require.Empty(t, rec.Body.Bytes())
	}

	// After a rotation the content changes, so does the ETag.
	f.rotate(t)
	rec = f.get(t, "/r/acme/.well-known/jwks.json", http.Header{"If-None-Match": {etag}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEqual(t, etag, rec.Header().Get("ETag"))
}

func TestJWKS_Head(t *testing.T) {
	f := newJWKSFixture(t)
	f.rotate(t)
	req := httptest.NewRequest(http.MethodHead, "/r/acme/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	f.server.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, rec.Header().Get("ETag"))
}

func TestJWKS_Realms(t *testing.T) {
	f := newJWKSFixture(t)

	rec := f.get(t, "/r/empty/.well-known/jwks.json", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"keys":[]}`, rec.Body.String(), "a realm without keys is a valid, empty JWK Set")

	require.Equal(t, http.StatusNotFound, f.get(t, "/r/unknown/.well-known/jwks.json", nil).Code)
	require.Equal(t, http.StatusNotFound, f.get(t, "/r/closed/.well-known/jwks.json", nil).Code)
}

func TestJWKS_PublishesOnlyThisRealmsJWTVerificationKeys(t *testing.T) {
	f := newJWKSFixture(t)
	active := f.rotate(t)
	rotating := active
	active = f.rotate(t)

	add := func(kid, realmID string, purpose domain.SigningKeyPurpose, status domain.SigningKeyStatus, pem string) {
		f.keys.Add(&domain.SigningKey{Kid: kid, RealmID: realmID, KeyType: domain.SigningKeyRSA,
			Purpose: purpose, Status: status, PublicKey: pem, CreatedAt: f.now.Add(-time.Hour)})
	}
	pem := active.PublicKey
	add("saml-signing", f.realm.ID, domain.SigningKeyPurposeSAMLSigning, domain.SigningKeyActive, pem)
	add("envelope", f.realm.ID, domain.SigningKeyPurposeEnvelopeEncrypt, domain.SigningKeyActive, pem)
	add("retired", f.realm.ID, domain.SigningKeyPurposeJWT, domain.SigningKeyRetired, pem)
	add("other-realm", "realm-empty", domain.SigningKeyPurposeJWT, domain.SigningKeyActive, pem)
	add("broken-pem", f.realm.ID, domain.SigningKeyPurposeJWT, domain.SigningKeyActive, "not a pem")

	set := f.fetchJWKS(t)

	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	require.Equal(t, []string{active.Kid, rotating.Kid}, kids,
		"no SAML/envelope key, no retired key, no other realm, broken key skipped without failing the set")
}

type failingKeySource struct{}

func (failingKeySource) PublicKeys(context.Context, string, domain.SigningKeyPurpose) ([]*domain.SigningKey, error) {
	return nil, errors.New("db down")
}

func TestJWKS_ErrorIsNeverCached(t *testing.T) {
	realms := &jwksRealms{byName: map[string]*domain.Realm{"acme": {ID: "r", Name: "acme", Status: domain.RealmActive}}}
	srv := httpserver.New(nil, nil, nil, realms, nil, nil, httpserver.WithJWKS(failingKeySource{}))

	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/r/acme/.well-known/jwks.json", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestJWKS_NotMountedWithoutOption(t *testing.T) {
	realms := &jwksRealms{byName: map[string]*domain.Realm{"acme": {ID: "r", Name: "acme", Status: domain.RealmActive}}}
	srv := httpserver.New(nil, nil, nil, realms, nil, nil)

	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/r/acme/.well-known/jwks.json", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}
