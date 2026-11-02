package repository_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

func TestCreateAuditLogParams_Normalized(t *testing.T) {
	t.Run("a user on their own account is actor and target", func(t *testing.T) {
		p := repository.CreateAuditLogParams{UserID: "alice", Action: "user.profile_updated"}.Normalized()
		require.Equal(t, domain.AuditActorUser, p.ActorType)
		require.Equal(t, "alice", p.TargetUserID)
		require.Equal(t, domain.AuditLogInfo, p.Level)
		require.Equal(t, domain.AuditLogSuccess, p.Status)
	})
	t.Run("nobody: the system, the User resource is the target", func(t *testing.T) {
		p := repository.CreateAuditLogParams{Action: "user.locked", ResourceType: "User", ResourceID: "alice"}.Normalized()
		require.Equal(t, domain.AuditActorSystem, p.ActorType)
		require.Empty(t, p.UserID)
		require.Equal(t, "alice", p.TargetUserID)
	})
	t.Run("explicit values are kept", func(t *testing.T) {
		p := repository.CreateAuditLogParams{UserID: "root", ActorType: domain.AuditActorAdmin, TargetUserID: "bob",
			ResourceType: "Session", ResourceID: "s1"}.Normalized()
		require.Equal(t, domain.AuditActorAdmin, p.ActorType)
		require.Equal(t, "bob", p.TargetUserID)
	})
}

func TestAuditActorFromTrigger(t *testing.T) {
	cases := []struct {
		by, target string
		typ        domain.AuditActorType
		id         string
	}{
		{"user:root", "alice", domain.AuditActorAdmin, "root"},
		{"user:alice", "alice", domain.AuditActorUser, "alice"},
		{"user:root", "", domain.AuditActorAdmin, "root"},
		{"cli:ops", "alice", domain.AuditActorCLI, ""},
		{"cli", "", domain.AuditActorCLI, ""},
		{"system", "", domain.AuditActorSystem, ""},
		{"system:config-apply", "", domain.AuditActorSystem, ""},
		{"", "", domain.AuditActorSystem, ""},
	}
	for _, c := range cases {
		typ, id := domain.AuditActorFromTrigger(c.by, c.target)
		require.Equal(t, c.typ, typ, c.by)
		require.Equal(t, c.id, id, c.by)
	}
}
