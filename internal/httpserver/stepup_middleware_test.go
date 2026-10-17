package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/memstore"
)

type fakeUserByID struct {
	repository.UserRepository // nil: other methods panic, on purpose
	user                      *domain.User
}

func (f *fakeUserByID) GetByID(_ context.Context, id string) (*domain.User, error) {
	if f.user != nil && f.user.ID == id {
		return f.user, nil
	}
	return nil, repository.ErrNotFound
}

func TestRequireStepUp(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	user := &domain.User{ID: "user-1", RealmID: "realm-1", Username: "alice", Status: domain.UserActive}
	methods := memstore.NewMfaMethods(clock)
	mfa := service.NewMFAService(service.MFADeps{
		Users:       &fakeUserByID{user: user},
		Methods:     methods,
		BackupCodes: memstore.NewMfaBackupCodes(clock),
		Policy:      service.NewMFAPolicyService(service.MFAPolicyDeps{Now: clock}),
		Now:         clock,
	})

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	call := func(s *Server, sess *domain.Session, mode service.StepUpMode) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/r/acme/account/mfa/backup-codes", nil)
		if sess != nil {
			req = req.WithContext(context.WithValue(req.Context(), sessionContextKey{}, sess))
		}
		rec := httptest.NewRecorder()
		s.requireStepUp(mode)(ok).ServeHTTP(rec, req)
		return rec
	}

	t.Run("no MFA service: no-op", func(t *testing.T) {
		require.Equal(t, http.StatusTeapot, call(&Server{}, nil, service.StepUpSensitiveAction).Code)
	})

	s := &Server{mfa: mfa}

	t.Run("no session", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, call(s, nil, service.StepUpAccountSecurity).Code)
	})

	t.Run("no factor: a fresh login passes, an old one must log in again", func(t *testing.T) {
		fresh := &domain.Session{ID: "s1", RealmID: "realm-1", UserID: "user-1", CreatedAt: now.Add(-time.Minute)}
		require.Equal(t, http.StatusTeapot, call(s, fresh, service.StepUpSensitiveAction).Code)

		old := &domain.Session{ID: "s2", RealmID: "realm-1", UserID: "user-1", CreatedAt: now.Add(-time.Hour)}
		rec := call(s, old, service.StepUpSensitiveAction)
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.JSONEq(t, `{"error":"recent_login_required","max_age_seconds":600}`, rec.Body.String())
	})

	t.Run("with a factor: a recent second factor is needed", func(t *testing.T) {
		_, err := methods.Create(context.Background(), repository.CreateMfaMethodParams{UserID: "user-1", Type: domain.MfaMethodTOTP})
		require.NoError(t, err)

		passwordOnly := &domain.Session{ID: "s3", RealmID: "realm-1", UserID: "user-1", CreatedAt: now}
		rec := call(s, passwordOnly, service.StepUpAccountSecurity)
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.JSONEq(t, `{"error":"step_up_required","max_age_seconds":600}`, rec.Body.String())

		verified := &domain.Session{ID: "s4", RealmID: "realm-1", UserID: "user-1", CreatedAt: now.Add(-time.Hour),
			MFAVerified: true, MFAMethodType: "totp", MFAVerifiedAt: now.Add(-5 * time.Minute)}
		require.Equal(t, http.StatusTeapot, call(s, verified, service.StepUpAccountSecurity).Code)

		verified.MFAVerifiedAt = now.Add(-11 * time.Minute)
		require.Equal(t, http.StatusForbidden, call(s, verified, service.StepUpAccountSecurity).Code)
	})
}
