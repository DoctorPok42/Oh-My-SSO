package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

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

func TestRequireJSON(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for ct, want := range map[string]int{
		"application/json":                  http.StatusNoContent,
		"application/json; charset=utf-8":   http.StatusNoContent,
		"":                                  http.StatusUnsupportedMediaType,
		"text/plain":                        http.StatusUnsupportedMediaType,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType, // what an HTML form sends
	} {
		req := httptest.NewRequest(http.MethodPost, "/r/acme/auth/step-up", strings.NewReader("{}"))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		requireJSON(next).ServeHTTP(rec, req)
		require.Equal(t, want, rec.Code, ct)
	}
}

func TestPublicServer_HasNoAdminRoutes(t *testing.T) {
	realm := &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	s := New(nil, nil, nil, &fakeRealmByName{realm: realm}, nil, nil)
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/r/acme/admin/signing-keys/", nil),
		httptest.NewRequest(http.MethodPost, "/r/acme/admin/signing-keys/rotate", strings.NewReader("{}")),
	} {
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, r)
		require.Equal(t, http.StatusNotFound, rec.Code, r.URL.Path)
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
