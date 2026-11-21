package service_test

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// acctExports is DataExportRepository in memory, with the rules of the
// database: one export per user, a running one kept until it is stale.
type acctExports struct {
	mu     sync.Mutex
	byUser map[string]*domain.DataExport
	n      int
}

func (r *acctExports) Start(_ context.Context, e *domain.DataExport, staleBefore time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.byUser[e.UserID]; ok && cur.Status == domain.DataExportRunning && !cur.CreatedAt.Before(staleBefore) {
		return repository.ErrConflict
	}
	r.n++
	e.ID, e.Status = "export-"+strconv.Itoa(r.n), domain.DataExportRunning
	cp := *e
	r.byUser[e.UserID] = &cp
	return nil
}

func (r *acctExports) Finish(_ context.Context, id string, status domain.DataExportStatus, data []byte, at, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byUser {
		if e.ID == id && e.Status == domain.DataExportRunning {
			e.Status, e.Data, e.FinishedAt, e.ExpiresAt = status, data, &at, expiresAt
		}
	}
	return nil
}

func (r *acctExports) GetByUser(_ context.Context, userID string) (*domain.DataExport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byUser[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *e
	cp.Data = nil // like the database: the status without the data
	return &cp, nil
}

func (r *acctExports) GetData(_ context.Context, id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byUser {
		if e.ID == id {
			return e.Data, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (a *acctAdmin) Memberships(_ context.Context, ids []string) (map[string]repository.Memberships, error) {
	out := map[string]repository.Memberships{}
	for _, id := range ids {
		out[id] = repository.Memberships{GroupIDs: []string{"g1"}, RoleIDs: []string{"r1"},
			Names: map[string]string{"g1": "staff", "r1": "payroll-reader"}}
	}
	return out, nil
}

var acctRealmObj = &domain.Realm{ID: acctRealm, Name: "acme", DisplayName: "Acme"}

func TestAccount_DataExport(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	sess := f.session(t, f.user)
	f.token(sess.ID, "c-wiki")
	f.consents.rows["consent-1"] = &domain.Consent{ID: "consent-1", UserID: f.user.ID, ClientRefID: "c-payroll",
		Scopes: []string{"openid", "payroll.read"}, Status: domain.ConsentGranted, GrantedAt: f.clock.Now()}
	_, err := f.mfa.Create(ctx, repository.CreateMfaMethodParams{UserID: f.user.ID, Type: domain.MfaMethodTOTP,
		Name: "Phone", SecretEncrypted: "TOTP-SECRET-CIPHERTEXT"})
	require.NoError(t, err)
	f.attempts.rows = []*domain.LoginAttempt{{UserID: f.user.ID, RealmID: acctRealm, IPAddress: "198.51.100.7",
		Status: domain.LoginAttemptSuccess, CreatedAt: f.clock.Now()}}
	f.admin.audit = []*domain.AuditLog{
		{Action: "user.profile_updated", UserID: f.user.ID, TargetUserID: f.user.ID, ActorType: domain.AuditActorUser,
			IPAddress: "198.51.100.7", Timestamp: f.clock.Now()},
		{Action: "mfa.reset", UserID: "u-admin", TargetUserID: f.user.ID, ActorType: domain.AuditActorAdmin,
			IPAddress: "203.0.113.9", Timestamp: f.clock.Now(),
			Details: map[string]interface{}{"admin_username": "root-operator", "admin_realm": "master", "reason": "lost phone"}},
		// dana, an administrator, deleted eve: eve's data, not dana's
		{Action: "user.deleted", UserID: f.user.ID, TargetUserID: f.other.ID, ActorType: domain.AuditActorAdmin,
			Details: map[string]interface{}{"email": "eve@example.test"}, Timestamp: f.clock.Now()},
		// dana imported accounts: about nobody, and full of other people
		{Action: "user.import_finished", UserID: f.user.ID, ActorType: domain.AuditActorAdmin, Timestamp: f.clock.Now(),
			Details: map[string]interface{}{"created_users": []interface{}{map[string]interface{}{"email": "frank@example.test"}}}},
	}

	e, err := f.svc.RequestDataExport(ctx, acctRealmObj, user, ev)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportRunning, e.Status)
	f.svc.StopDataExports(ctx) // waits for the copy

	got, err := f.svc.DataExport(ctx, user)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportReady, got.Status)
	require.Equal(t, f.clock.Now().Add(service.DataExportTTL), got.ExpiresAt)
	require.Nil(t, got.Data, "the status does not carry the copy")

	dl, err := f.svc.DownloadDataExport(ctx, user, ev)
	require.NoError(t, err)
	require.Equal(t, []string{"user.data_export_requested:success", "user.data_exported:success"}, f.actions())
	raw := string(dl.Data)
	require.NotContains(t, raw, user.PasswordHash, "no password hash")
	require.NotContains(t, raw, "TOTP-SECRET-CIPHERTEXT", "no second-factor secret")
	require.NotContains(t, raw, "eve@example.test", "nothing about another user")
	require.NotContains(t, raw, "frank@example.test", "nor what dana did as an administrator about nobody")
	require.NotContains(t, raw, "203.0.113.9", "not the address of an administrator")
	require.NotContains(t, raw, "root-operator", "not the name of an administrator")
	require.Contains(t, raw, "lost phone", "what was done stays")

	var doc struct {
		Format       string                `json:"format"`
		Organization struct{ Name string } `json:"organization"`
		Account      struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"account"`
		Groups        []string                  `json:"groups"`
		Roles         []string                  `json:"roles"`
		SecondFactors []map[string]any          `json:"second_factors"`
		Sessions      []map[string]any          `json:"sessions"`
		Applications  []struct{ Name string }   `json:"applications"`
		SignIns       []map[string]any          `json:"sign_ins"`
		Activity      []struct{ Action string } `json:"activity"`
		Truncated     []string                  `json:"truncated"`
	}
	require.NoError(t, json.Unmarshal(dl.Data, &doc))
	require.Equal(t, service.DataExportFormat, doc.Format)
	require.Equal(t, "acme", doc.Organization.Name)
	require.Equal(t, "dana", doc.Account.Username)
	require.Equal(t, "dana@example.test", doc.Account.Email)
	require.Equal(t, []string{"staff"}, doc.Groups)
	require.Equal(t, []string{"payroll-reader"}, doc.Roles)
	require.Len(t, doc.SecondFactors, 1)
	require.Equal(t, "Phone", doc.SecondFactors[0]["name"])
	require.Len(t, doc.Sessions, 1)
	require.Len(t, doc.Applications, 2) // Payroll (approved), Wiki (signed in)
	require.Len(t, doc.SignIns, 1)
	require.Equal(t, []struct{ Action string }{{"user.profile_updated"}, {"mfa.reset"}}, doc.Activity)
	require.Empty(t, doc.Truncated)

	ready := f.notifier.last()
	require.Equal(t, domain.NotificationDataExportReady, ready.Kind)
	require.Equal(t, f.user.ID, ready.UserID)
	require.Equal(t, got.ExpiresAt, ready.ExpiresAt)

	f.clock.Advance(service.DataExportTTL)
	gone, err := f.svc.DataExport(ctx, user)
	require.NoError(t, err)
	require.Nil(t, gone, "expired: as if there were none")
	_, err = f.svc.DownloadDataExport(ctx, user, ev)
	require.ErrorIs(t, err, service.ErrDataExportNotReady)
}

// Past 10 000 sign-ins, the copy keeps the newest and says it was cut; at
// exactly 10 000, nothing is cut.
func TestAccount_DataExport_KeepsTheNewestRows(t *testing.T) {
	for _, c := range []struct {
		rows int
		cut  []string
	}{{10001, []string{"sign_ins"}}, {10000, nil}} {
		t.Run(strconv.Itoa(c.rows), func(t *testing.T) {
			f := newAcctFixture(t)
			ctx := context.Background()
			user := f.users.get(f.user.ID)
			newest := f.clock.Now()
			f.attempts.rows = nil
			for i := 0; i < c.rows; i++ { // newest first, like the database
				f.attempts.rows = append(f.attempts.rows, &domain.LoginAttempt{UserID: user.ID, RealmID: acctRealm,
					Status: domain.LoginAttemptSuccess, CreatedAt: newest.Add(-time.Duration(i) * time.Second)})
			}
			_, err := f.svc.RequestDataExport(ctx, acctRealmObj, user, ev)
			require.NoError(t, err)
			f.svc.StopDataExports(ctx)
			dl, err := f.svc.DownloadDataExport(ctx, user, ev)
			require.NoError(t, err)

			var doc struct {
				SignIns   []struct{ At time.Time } `json:"sign_ins"`
				Truncated []string                 `json:"truncated"`
			}
			require.NoError(t, json.Unmarshal(dl.Data, &doc))
			require.Len(t, doc.SignIns, 10000)
			require.Equal(t, c.cut, doc.Truncated)
			require.True(t, doc.SignIns[0].At.Equal(newest), "the newest is kept")
		})
	}
}

func TestAccount_DataExport_OneAtATime(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	// A copy being made by another server.
	f.exports.byUser[user.ID] = &domain.DataExport{ID: "elsewhere", UserID: user.ID, Status: domain.DataExportRunning,
		CreatedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(service.DataExportTTL)}

	_, err := f.svc.RequestDataExport(ctx, acctRealmObj, user, ev)
	require.ErrorIs(t, err, service.ErrDataExportRunning)
	_, err = f.svc.DownloadDataExport(ctx, user, ev)
	require.ErrorIs(t, err, service.ErrDataExportNotReady, "not ready yet")

	// Its server stopped: after a while it shows as failed, and a new
	// request replaces it.
	f.clock.Advance(16 * time.Minute)
	stale, err := f.svc.DataExport(ctx, user)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportFailed, stale.Status)

	_, err = f.svc.RequestDataExport(ctx, acctRealmObj, user, ev)
	require.NoError(t, err)
	f.svc.StopDataExports(ctx)
	got, err := f.svc.DataExport(ctx, user)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportReady, got.Status)

	_, err = f.svc.RequestDataExport(ctx, acctRealmObj, user, ev)
	require.ErrorIs(t, err, service.ErrDataExportStopping, "a stopping server takes no new copy")
}

func TestAccount_DataExport_FailureIsShown(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	ghost := &domain.User{ID: "u-ghost", RealmID: acctRealm} // not in the users store: the copy cannot be made

	_, err := f.svc.RequestDataExport(ctx, acctRealmObj, ghost, ev)
	require.NoError(t, err)
	f.svc.StopDataExports(ctx)
	got, err := f.svc.DataExport(ctx, ghost)
	require.NoError(t, err)
	require.Equal(t, domain.DataExportFailed, got.Status)
	require.Empty(t, got.Data)
	require.NotContains(t, f.notifier.kinds(), domain.NotificationDataExportReady)

	none, err := f.svc.DataExport(ctx, user)
	require.NoError(t, err)
	require.Nil(t, none)
}
