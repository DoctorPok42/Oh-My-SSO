package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

type fakeKeyRotator struct {
	rotateIn  *service.RotateInput
	rotateRes *service.RotateResult
	rotateErr error

	retiredBy  string
	retired    []*domain.SigningKey
	retireErr  error
	listResult []*domain.SigningKey

	activateIn  *service.ActivateInput
	activateRes *service.RotateResult
	activateErr error
}

type fakeRealmByName struct {
	repository.RealmRepository // nil: other methods panic, on purpose
	realm                      *domain.Realm
}

func (f *fakeRealmByName) GetByName(_ context.Context, name string) (*domain.Realm, error) {
	if f.realm != nil && f.realm.Name == name {
		return f.realm, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeKeyRotator) Rotate(_ context.Context, in service.RotateInput) (*service.RotateResult, error) {
	f.rotateIn = &in
	return f.rotateRes, f.rotateErr
}

func (f *fakeKeyRotator) Activate(_ context.Context, in service.ActivateInput) (*service.RotateResult, error) {
	f.activateIn = &in
	return f.activateRes, f.activateErr
}

func (f *fakeKeyRotator) RetireExpired(_ context.Context, _ string, by string) ([]*domain.SigningKey, error) {
	f.retiredBy = by
	return f.retired, f.retireErr
}

func (f *fakeKeyRotator) List(context.Context, string) ([]*domain.SigningKey, error) {
	return f.listResult, nil
}

var (
	testAdminRealm = &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	testAdminSess  = &domain.Session{ID: "s1", RealmID: "realm-1", UserID: "user-1"}
	testNewKey     = &domain.SigningKey{Kid: "kid-new", KeyType: domain.SigningKeyRSA, Purpose: domain.SigningKeyPurposeJWT,
		Status: domain.SigningKeyActive, KMSKeyReference: "vault-secret-ref", CreatedAt: time.Unix(1_800_000_000, 0)}
)

// adminRequest builds a request as it looks after realmMiddleware,
// requireSession and requirePermission (tested on their own) let it through.
func adminRequest(method, body, contentType string) *http.Request {
	req := httptest.NewRequest(method, "/r/acme/admin/signing-keys/rotate", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	ctx := context.WithValue(req.Context(), realmContextKey{}, testAdminRealm)
	ctx = context.WithValue(ctx, sessionContextKey{}, testAdminSess)
	return req.WithContext(ctx)
}

func TestHandleRotateSigningKey(t *testing.T) {
	ok := &service.RotateResult{NewKey: testNewKey, Grace: 48 * time.Hour}

	tests := []struct {
		name       string
		body       string
		res        *service.RotateResult
		err        error
		wantStatus int
		wantBody   string // substring
	}{
		{"defaults with empty body", "", ok, nil, http.StatusOK, `"kid":"kid-new"`},
		{"all options", `{"key_type":"EC","grace_hours":48,"reason":"yearly"}`, ok, nil, http.StatusOK, `"grace_hours":48`},
		{"unknown field is refused", `{"compromized":true}`, nil, nil, http.StatusBadRequest, "invalid_request"},
		{"negative grace", `{"grace_hours":-1}`, nil, nil, http.StatusBadRequest, "invalid_request"},
		{"unsupported key type", `{"key_type":"HS256"}`, nil, nil, http.StatusBadRequest, "unsupported_key_type"},
		{"grace too short", `{"grace_hours":0}`, nil, service.ErrGraceTooShort, http.StatusBadRequest, "grace_too_short"},
		{"compromised without reason", `{"compromised":true}`, nil, service.ErrCompromisedReasonRequired, http.StatusBadRequest, "reason_required"},
		{"technical error", `{}`, nil, errors.New("vault down"), http.StatusInternalServerError, "internal_error"},
		{"partial failure still reports the new key", `{}`, ok, errors.New("log write failed"), http.StatusOK, `"warning"`},
		// Step 11
		{"saml purpose", `{"purpose":"saml_signing"}`, ok, nil, http.StatusOK, `"kid":"kid-new"`},
		{"other purposes are refused", `{"purpose":"envelope_encryption"}`, nil, nil, http.StatusBadRequest, "unsupported_purpose"},
		{"saml key must be RSA", `{"purpose":"saml_signing","key_type":"EC"}`, nil, service.ErrSAMLKeyMustBeRSA, http.StatusBadRequest, "unsupported_key_type"},
		{"a pending key already waits", `{"purpose":"saml_signing"}`, nil, service.ErrPendingKeyExists, http.StatusConflict, "pending_key_exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rot := &fakeKeyRotator{rotateRes: tt.res, rotateErr: tt.err}
			s := &Server{keyRotator: rot}
			rec := httptest.NewRecorder()

			s.handleRotateSigningKey(rec, adminRequest(http.MethodPost, tt.body, "application/json"))

			require.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), tt.wantBody)
			require.NotContains(t, rec.Body.String(), "vault-secret-ref", "the KMS reference is never shown")
		})
	}

	t.Run("input passed to the service", func(t *testing.T) {
		rot := &fakeKeyRotator{rotateRes: ok}
		s := &Server{keyRotator: rot}
		body := `{"key_type":"EC","grace_hours":36,"compromised":true,"reason":"leak"}`

		s.handleRotateSigningKey(httptest.NewRecorder(), adminRequest(http.MethodPost, body, "application/json"))

		require.Equal(t, service.RotateInput{
			RealmID:     "realm-1",
			Purpose:     domain.SigningKeyPurposeJWT,
			KeyType:     domain.SigningKeyEC,
			Grace:       36 * time.Hour,
			Compromised: true,
			TriggeredBy: "user:user-1",
			Reason:      "leak",
		}, *rot.rotateIn)
	})
}

func TestHandleActivateSigningKey(t *testing.T) {
	ok := &service.RotateResult{NewKey: testNewKey, Grace: 24 * time.Hour}
	tests := []struct {
		name       string
		body       string
		res        *service.RotateResult
		err        error
		wantStatus int
		wantBody   string
	}{
		{"defaults", "", ok, nil, http.StatusOK, `"kid":"kid-new"`},
		{"no pending key", `{}`, nil, service.ErrNoPendingKey, http.StatusConflict, "no_pending_key"},
		{"one-step purpose", `{"purpose":"jwt_signing"}`, nil, service.ErrActivationNotSupported, http.StatusBadRequest, "unsupported_purpose"},
		{"unknown field", `{"force":true}`, nil, nil, http.StatusBadRequest, "invalid_request"},
		{"technical error", `{}`, nil, errors.New("db down"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rot := &fakeKeyRotator{activateRes: tt.res, activateErr: tt.err}
			s := &Server{keyRotator: rot}
			rec := httptest.NewRecorder()
			s.handleActivateSigningKey(rec, adminRequest(http.MethodPost, tt.body, "application/json"))
			require.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), tt.wantBody)
		})
	}

	t.Run("input passed to the service", func(t *testing.T) {
		rot := &fakeKeyRotator{activateRes: ok}
		s := &Server{keyRotator: rot}
		s.handleActivateSigningKey(httptest.NewRecorder(),
			adminRequest(http.MethodPost, `{"grace_hours":30,"reason":"planned"}`, "application/json"))
		require.Equal(t, service.ActivateInput{
			RealmID:     "realm-1",
			Purpose:     domain.SigningKeyPurposeSAMLSigning,
			Grace:       30 * time.Hour,
			TriggeredBy: "user:user-1",
			Reason:      "planned",
		}, *rot.activateIn)
	})
}

func TestHandleRetireExpiredSigningKeys(t *testing.T) {
	rot := &fakeKeyRotator{retired: []*domain.SigningKey{testNewKey}}
	s := &Server{keyRotator: rot}
	rec := httptest.NewRecorder()

	s.handleRetireExpiredSigningKeys(rec, adminRequest(http.MethodPost, "", "application/json"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"kid":"kid-new"`)
	require.Equal(t, "user:user-1", rot.retiredBy)

	rot.retireErr = errors.New("db down")
	rec = httptest.NewRecorder()
	s.handleRetireExpiredSigningKeys(rec, adminRequest(http.MethodPost, "", "application/json"))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleListSigningKeys(t *testing.T) {
	s := &Server{keyRotator: &fakeKeyRotator{}}
	rec := httptest.NewRecorder()
	s.handleListSigningKeys(rec, adminRequest(http.MethodGet, "", ""))
	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"keys":[]}`, rec.Body.String())
}

func TestRequireJSON(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for ct, want := range map[string]int{
		"application/json":                  http.StatusNoContent,
		"application/json; charset=utf-8":   http.StatusNoContent,
		"":                                  http.StatusUnsupportedMediaType,
		"text/plain":                        http.StatusUnsupportedMediaType,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType, // what an HTML form sends
	} {
		rec := httptest.NewRecorder()
		requireJSON(next).ServeHTTP(rec, adminRequest(http.MethodPost, "{}", ct))
		require.Equal(t, want, rec.Code, ct)
	}
}

func TestSigningKeyAdmin_RequiresASession(t *testing.T) {
	s := New(nil, nil, nil, &fakeRealmByName{realm: testAdminRealm}, nil, nil, WithSigningKeyAdmin(&fakeKeyRotator{}))
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/r/acme/admin/signing-keys/", nil),
		httptest.NewRequest(http.MethodPost, "/r/acme/admin/signing-keys/rotate", strings.NewReader("{}")),
		httptest.NewRequest(http.MethodPost, "/r/acme/admin/signing-keys/retire-expired", nil),
	} {
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, r)
		require.Equal(t, http.StatusUnauthorized, rec.Code, r.URL.Path)
	}
}

func TestETagMatches(t *testing.T) {
	const etag = `"abc"`
	for header, want := range map[string]bool{
		"":           false,
		`"abc"`:      true,
		`W/"abc"`:    true,
		`"x", "abc"`: true,
		`"x","y"`:    false,
		"*":          true,
		`"abcd"`:     false,
		`abc`:        false,
	} {
		require.Equal(t, want, etagMatches(header, etag), header)
	}
}
