package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

type fakeAuthorizer struct {
	err   error
	calls []service.AuthorizeInput
}

func (f *fakeAuthorizer) Authorize(_ context.Context, in service.AuthorizeInput) error {
	f.calls = append(f.calls, in)
	return f.err
}

type fakeClientRepo struct {
	repository.ClientRepository // nil: any other method would panic, on purpose
	client                      *domain.ClientApp
	err                         error
}

func (f *fakeClientRepo) GetByRealmAndClientID(_ context.Context, realmID, clientID string) (*domain.ClientApp, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.client == nil || f.client.RealmID != realmID || f.client.ClientID != clientID {
		return nil, repository.ErrNotFound
	}
	return f.client, nil
}

func TestRequirePermission(t *testing.T) {
	realm := &domain.Realm{ID: "realm-1", Name: "acme", Status: domain.RealmActive}
	adminClient := &domain.ClientApp{ID: "client-ref-1", RealmID: realm.ID, ClientID: domain.InternalAdminClientID}
	sess := &domain.Session{ID: "s1", RealmID: realm.ID, UserID: "user-1"}

	tests := []struct {
		name          string
		withSession   bool
		clients       *fakeClientRepo
		authzErr      error
		wantStatus    int
		wantNext      bool
		wantClientRef string
	}{
		{"allowed", true, &fakeClientRepo{client: adminClient}, nil, http.StatusOK, true, "client-ref-1"},
		{"refused", true, &fakeClientRepo{client: adminClient}, service.ErrForbidden, http.StatusForbidden, false, "client-ref-1"},
		{"technical error", true, &fakeClientRepo{client: adminClient}, errors.New("db down"), http.StatusInternalServerError, false, "client-ref-1"},
		{"no session", false, &fakeClientRepo{client: adminClient}, nil, http.StatusUnauthorized, false, ""},
		{"internal client missing is delegated to the service", true, &fakeClientRepo{}, service.ErrForbidden, http.StatusForbidden, false, ""},
		{"client lookup failure", true, &fakeClientRepo{err: errors.New("db down")}, nil, http.StatusInternalServerError, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authz := &fakeAuthorizer{err: tt.authzErr}
			s := &Server{authz: authz, clients: tt.clients}

			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})
			handler := s.requirePermission("client", "create")(next)

			req := httptest.NewRequest(http.MethodPost, "/r/acme/clients", nil)
			ctx := context.WithValue(req.Context(), realmContextKey{}, realm)
			if tt.withSession {
				ctx = context.WithValue(ctx, sessionContextKey{}, sess)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req.WithContext(ctx))

			require.Equal(t, tt.wantStatus, rec.Code)
			require.Equal(t, tt.wantNext, nextCalled)

			if tt.wantStatus == http.StatusUnauthorized || tt.clients.err != nil {
				require.Empty(t, authz.calls, "authorizer must not be reached")
				return
			}
			require.Len(t, authz.calls, 1)
			got := authz.calls[0]
			require.Equal(t, realm.ID, got.RealmID)
			require.Equal(t, "user-1", got.UserID)
			require.Equal(t, tt.wantClientRef, got.ClientRef)
			require.Equal(t, "client", got.Resource)
			require.Equal(t, "create", got.Action)
		})
	}
}
