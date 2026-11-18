package entstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/metrics/metricstest"
	"sso.internal/sso/internal/storage/entstore"
)

// The audit entries and tokens written feed /metrics (sign-ins, failures,
// tokens issued).
func TestCreateFeedsTheMetrics_Integration(t *testing.T) {
	f := newRBACFixture(t)
	u := f.user()

	failed := map[string]string{"action": audit.AuthLoginFailed, "status": string(domain.AuditLogFailure)}
	before := metricstest.Value(t, "omsso_audit_events_total", failed)
	_, err := entstore.NewAuditLogRepository(f.client).Create(f.ctx, repository.CreateAuditLogParams{
		RealmID: f.realm.ID, TargetUserID: u.ID, Action: audit.AuthLoginFailed, Status: domain.AuditLogFailure,
	})
	require.NoError(t, err)
	require.Equal(t, before+1, metricstest.Value(t, "omsso_audit_events_total", failed))

	sess, err := entstore.NewSessionRepository(f.client).Create(f.ctx, repository.CreateSessionParams{
		RealmID: f.realm.ID, UserID: u.ID, TokenHash: "hash-" + f.suffix(),
		ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(t, err)
	access := map[string]string{"type": string(domain.TokenAccessToken)}
	before = metricstest.Value(t, "omsso_tokens_issued_total", access)
	_, err = entstore.NewTokenRepository(f.client).Create(f.ctx, repository.CreateTokenParams{
		SessionID: sess.ID, ClientRefID: f.clientApp("metrics").ID, Type: domain.TokenAccessToken,
		JTI: "jti-" + f.suffix(), ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	require.Equal(t, before+1, metricstest.Value(t, "omsso_tokens_issued_total", access))
}
