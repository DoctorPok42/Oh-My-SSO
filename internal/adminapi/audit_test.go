package adminapi

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

func TestAuditSearch_Filters(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?action=auth.*&actor=admin,cli&status=failure&level=warning&from=2026-10-01&to=2026-10-31&user=u1", nil)
	f, bad := auditSearch(r)
	require.Empty(t, bad)
	require.Equal(t, "auth.", f.ActionPrefix)
	require.Empty(t, f.Action)
	require.Equal(t, []domain.AuditActorType{domain.AuditActorAdmin, domain.AuditActorCLI}, f.ActorTypes)
	require.Equal(t, domain.AuditLogFailure, f.Status)
	require.Equal(t, []domain.AuditLogLevel{domain.AuditLogWarning}, f.Levels)
	require.Equal(t, "u1", f.UserID)
	require.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), f.To.UTC(), "a date: that whole day")

	f, bad = auditSearch(httptest.NewRequest("GET", "/x?action=user.locked", nil))
	require.Empty(t, bad)
	require.Equal(t, "user.locked", f.Action)

	for _, q := range []string{"actor=robot", "status=maybe", "level=loud", "from=yesterday"} {
		_, bad := auditSearch(httptest.NewRequest("GET", "/x?"+q, nil))
		require.NotEmpty(t, bad, q)
	}
}

func TestAuditCSVRow_NoFormulaInjection(t *testing.T) {
	row := auditCSVRow(service.AuditView{
		Timestamp: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), Action: "auth.login_failed",
		ActorType: domain.AuditActorAnonymous, Target: &service.AuditUserRef{ID: "u1", Username: "=HYPERLINK(\"x\")"},
		UserAgent: "+cmd", Details: map[string]interface{}{"reason": "invalid_credentials"},
	})
	require.Len(t, row, len(auditCSVHeader))
	require.Equal(t, "2026-11-02T10:00:00Z", row[0])
	require.Equal(t, "anonymous", row[4])
	require.Equal(t, "'=HYPERLINK(\"x\")", row[8])
	require.Equal(t, "'+cmd", row[12])
	require.Equal(t, `{"reason":"invalid_credentials"}`, row[13])
}
