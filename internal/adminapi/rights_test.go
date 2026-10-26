package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// fakeRBAC counts the calls that would read the database.
type fakeRBAC struct {
	allow     map[string]bool // "resource:action"
	authorize int
	effective int
}

func (f *fakeRBAC) Authorize(_ context.Context, in service.AuthorizeInput) error {
	f.authorize++
	if f.allow[in.Resource+":"+in.Action] {
		return nil
	}
	return service.ErrForbidden
}

func (f *fakeRBAC) GetEffectivePermissions(context.Context, string, string) ([]*domain.Permission, error) {
	f.effective++
	return nil, nil
}

type brokenEpoch struct{}

func (brokenEpoch) LastChange(context.Context) (time.Time, error) {
	return time.Time{}, errors.New("valkey down")
}
func (brokenEpoch) Changed(context.Context, time.Time) error { return errors.New("valkey down") }

func iat(t time.Time) *json.Number {
	n := json.Number(strconv.FormatInt(t.Unix(), 10))
	return &n
}

func TestTokenRights(t *testing.T) {
	s := New(Config{Now: func() time.Time { return t0 }}, Deps{Rights: &memoryEpoch{at: t0}})
	ents := []string{"user:read"}
	cases := []struct {
		name   string
		claims accessClaims
		want   bool
	}{
		{"no entitlements claim (older token)", accessClaims{IssuedAt: iat(t0.Add(time.Hour))}, false},
		{"no iat", accessClaims{Entitlements: ents}, false},
		{"issued before the last change", accessClaims{Entitlements: ents, IssuedAt: iat(t0.Add(-time.Minute))}, false},
		{"issued within the clock skew after it", accessClaims{Entitlements: ents, IssuedAt: iat(t0.Add(clockSkew))}, false},
		{"issued well after it", accessClaims{Entitlements: ents, IssuedAt: iat(t0.Add(clockSkew + time.Second))}, true},
	}
	for _, c := range cases {
		got, ok := s.tokenRights(context.Background(), &c.claims)
		if ok != c.want || (ok && len(got) != 1) {
			t.Errorf("%s: trusted=%v rights=%v, want trusted=%v", c.name, ok, got, c.want)
		}
	}

	broken := New(Config{Now: func() time.Time { return t0 }}, Deps{Rights: brokenEpoch{}})
	if _, ok := broken.tokenRights(context.Background(),
		&accessClaims{Entitlements: ents, IssuedAt: iat(t0.Add(time.Hour))}); ok {
		t.Error("epoch unavailable: the token must not be trusted")
	}
}

// adminRequest: a request that went through authenticate.
func adminRequest(method string, a *adminContext, realm *domain.Realm) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	ctx := context.WithValue(r.Context(), ctxAdmin, a)
	if realm != nil {
		ctx = context.WithValue(ctx, ctxRealm, realm)
	}
	return r.WithContext(ctx)
}

func testAdmin(rights []string, fromToken bool) *adminContext {
	return &adminContext{
		user:   &domain.User{ID: "u-root"},
		master: &domain.Realm{ID: "realm-master"}, client: &domain.ClientApp{ID: "c-sso-admin"},
		rights: rights, rightsFromToken: fromToken,
	}
}

func TestRequireUsesTheTokenAndTheDatabaseForRefusals(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	cases := []struct {
		name          string
		admin         *adminContext
		dbAllows      bool
		wantStatus    int
		wantDatabased int
	}{
		{"trusted token grants it: no database read", testAdmin([]string{"user:read"}, true), false, http.StatusNoContent, 0},
		{"trusted token lacks it, the database refuses (and audits)", testAdmin([]string{"audit_log:read"}, true), false, http.StatusForbidden, 1},
		{"trusted token lacks it, the database grants it (granted since)", testAdmin(nil, true), true, http.StatusNoContent, 1},
		{"token not trusted: the database decides", testAdmin([]string{"user:read"}, false), false, http.StatusForbidden, 1},
	}
	for _, c := range cases {
		rbac := &fakeRBAC{allow: map[string]bool{"user:read": c.dbAllows}}
		s := New(Config{}, Deps{RBAC: rbac})
		w := httptest.NewRecorder()
		s.require("user", "read")(ok).ServeHTTP(w, adminRequest(http.MethodGet, c.admin, nil))
		if w.Code != c.wantStatus || rbac.authorize != c.wantDatabased {
			t.Errorf("%s: status %d, %d database check(s); want %d, %d", c.name, w.Code, rbac.authorize, c.wantStatus, c.wantDatabased)
		}
	}
}

func TestRecordRightsChange(t *testing.T) {
	now := t0
	epoch := &memoryEpoch{at: t0.Add(-time.Hour)}
	s := New(Config{Now: func() time.Time { return now }}, Deps{Rights: epoch})
	var during time.Time
	change := s.recordRightsChange(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		during, _ = epoch.LastChange(r.Context())
		now = now.Add(2 * time.Second) // the change takes a while
		w.WriteHeader(http.StatusOK)
	}))
	admin := testAdmin(nil, true)

	// Elsewhere than master: nothing recorded.
	change.ServeHTTP(httptest.NewRecorder(), adminRequest(http.MethodPost, admin, &domain.Realm{ID: "realm-demo"}))
	if got, _ := epoch.LastChange(context.Background()); !got.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("a change in demo moved the epoch to %v", got)
	}

	// In master: before (tokens issued during the change are not trusted)
	// and after it.
	now = t0
	change.ServeHTTP(httptest.NewRecorder(), adminRequest(http.MethodPost, admin, admin.master))
	if !during.Equal(t0) {
		t.Errorf("epoch while the change runs: %v, want %v", during, t0)
	}
	if got, _ := epoch.LastChange(context.Background()); !got.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("epoch after the change: %v, want %v", got, t0.Add(2*time.Second))
	}

	// The time cannot be recorded: the change is refused, not run.
	ran := false
	refused := New(Config{Now: func() time.Time { return now }}, Deps{Rights: brokenEpoch{}}).
		recordRightsChange(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true }))
	w := httptest.NewRecorder()
	refused.ServeHTTP(w, adminRequest(http.MethodPost, admin, admin.master))
	if w.Code != http.StatusServiceUnavailable || ran {
		t.Errorf("epoch unavailable: status %d, handler ran=%v; want 503 and not run", w.Code, ran)
	}
}

func TestMemoryEpochNeverGoesBack(t *testing.T) {
	e := &memoryEpoch{at: t0}
	_ = e.Changed(context.Background(), t0.Add(-time.Minute))
	if got, _ := e.LastChange(context.Background()); !got.Equal(t0) {
		t.Fatalf("epoch moved back to %v", got)
	}
}
