package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

func TestAuditedLoginAttempts(t *testing.T) {
	ctx := context.Background()
	attempts, audit := &fakeLoginAttemptRepo{}, &fakeAuditRepo{}
	repo := service.AuditedLoginAttempts(attempts, audit, nil)

	_, err := repo.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID: "r1", UserID: "alice", Identifier: "alice", IPAddress: "198.51.100.7",
		Status: domain.LoginAttemptSuccess,
	})
	require.NoError(t, err)
	require.Empty(t, audit.entries, "a success is recorded once the session exists (auth.login)")

	_, err = repo.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID: "r1", UserID: "alice", Identifier: "alice", IPAddress: "198.51.100.7", UserAgent: "curl",
		Status: domain.LoginAttemptFailure, FailureReason: domain.LoginFailureInvalidCredentials,
	})
	require.NoError(t, err)
	_, err = repo.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID: "r1", Identifier: "nobody@example.com", Status: domain.LoginAttemptFailure,
		FailureReason: domain.LoginFailureUnknownAccount,
	})
	require.NoError(t, err)
	_, err = repo.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID: "r1", UserID: "alice", Status: domain.LoginAttemptFailure, FailureReason: domain.LoginFailureMfaFailed,
	})
	require.NoError(t, err)

	require.Len(t, attempts.attempts, 4, "every attempt still goes to LoginAttempt")
	require.Len(t, audit.entries, 3)

	wrong := audit.entries[0]
	require.Equal(t, "auth.login_failed", wrong.Action)
	require.Equal(t, domain.AuditActorAnonymous, wrong.ActorType)
	require.Empty(t, wrong.UserID, "whoever typed the password is not the actor on record")
	require.Equal(t, "alice", wrong.TargetUserID)
	require.Equal(t, "198.51.100.7", wrong.IPAddress)
	require.Equal(t, domain.AuditLogFailure, wrong.Status)
	require.Equal(t, "invalid_credentials", wrong.Details["reason"])

	unknown := audit.entries[1]
	require.Empty(t, unknown.TargetUserID)
	require.Empty(t, unknown.ResourceType)
	require.Equal(t, "nobody@example.com", unknown.Details["identifier"])

	require.Equal(t, "auth.mfa_failed", audit.entries[2].Action)
	require.Equal(t, domain.AuditLogWarning, audit.entries[2].Level)
}
