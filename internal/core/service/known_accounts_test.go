package service_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)

// "Pick an account": which accounts a device remembers and shows.

// fakeKnownAccounts is an in-memory KnownAccountRepository.
type fakeKnownAccounts struct {
	mu   sync.Mutex
	seq  int
	rows map[string]*domain.KnownAccount
}

func newFakeKnownAccounts() *fakeKnownAccounts {
	return &fakeKnownAccounts{rows: map[string]*domain.KnownAccount{}}
}

func (f *fakeKnownAccounts) Touch(_ context.Context, realmID, deviceHash, userID string, at time.Time) (*domain.KnownAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.DeviceHash == deviceHash && r.UserID == userID {
			r.LastUsedAt = at
			cp := *r
			return &cp, nil
		}
	}
	f.seq++
	r := &domain.KnownAccount{ID: fmt.Sprintf("ka-%d", f.seq), RealmID: realmID, UserID: userID,
		DeviceHash: deviceHash, CreatedAt: at, LastUsedAt: at}
	f.rows[r.ID] = r
	cp := *r
	return &cp, nil
}

func (f *fakeKnownAccounts) sorted(realmID, deviceHash string) []*domain.KnownAccount {
	var out []*domain.KnownAccount
	for _, r := range f.rows {
		if r.RealmID == realmID && r.DeviceHash == deviceHash {
			cp := *r
			out = append(out, &cp)
		}
	}
	slices.SortFunc(out, func(a, b *domain.KnownAccount) int { return b.LastUsedAt.Compare(a.LastUsedAt) })
	return out
}

func (f *fakeKnownAccounts) ListByDevice(_ context.Context, realmID, deviceHash string) ([]*domain.KnownAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sorted(realmID, deviceHash), nil
}

func (f *fakeKnownAccounts) GetByID(_ context.Context, id string) (*domain.KnownAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[id]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeKnownAccounts) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[id]; !ok {
		return repository.ErrNotFound
	}
	delete(f.rows, id)
	return nil
}

func (f *fakeKnownAccounts) Trim(_ context.Context, realmID, deviceHash string, keep int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.sorted(realmID, deviceHash)
	n := 0
	for i := keep; i < len(rows); i++ {
		delete(f.rows, rows[i].ID)
		n++
	}
	return n, nil
}

func (f *fakeKnownAccounts) Find(_ context.Context, realmID, deviceHash, userID string) (*domain.KnownAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.RealmID == realmID && r.DeviceHash == deviceHash && r.UserID == userID {
			cp := *r
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeKnownAccounts) SetLastMethods(_ context.Context, realmID, deviceHash, userID string, p repository.LastMethodsParams) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.RealmID == realmID && r.DeviceHash == deviceHash && r.UserID == userID {
			if p.LastMethod != nil {
				r.LastMethod = *p.LastMethod
			}
			if p.LastSecondFactor != nil {
				r.LastSecondFactor = *p.LastSecondFactor
			}
			return true, nil
		}
	}
	return false, nil
}

// Two devices: what the sso_device cookie holds (26 characters of base32).
const (
	deviceA = "AAAAAAAAAAAAAAAAAAAAAAAAAA"
	deviceB = "BBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type knownFixture struct {
	now      time.Time
	repo     *fakeKnownAccounts
	users    *fakeUserRepo
	audit    *fakeAuditRepo
	accounts *service.KnownAccountService
}

func newKnownFixture() *knownFixture {
	f := &knownFixture{now: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC), repo: newFakeKnownAccounts(), audit: &fakeAuditRepo{}}
	f.users = &fakeUserRepo{byID: map[string]*domain.User{
		aliceID: {ID: aliceID, RealmID: realmA, Username: "alice", Email: "alice@example.com", Status: domain.UserActive,
			Profile: map[string]interface{}{"given_name": "Alice", "family_name": "Martin"}},
		bobID: {ID: bobID, RealmID: realmA, Username: "bob", Status: domain.UserActive},
	}}
	f.accounts = service.NewKnownAccountService(service.KnownAccountDeps{
		Accounts: f.repo, Users: f.users, Audit: f.audit, Now: func() time.Time { return f.now },
	})
	return f
}

// signIn is what SessionService.Create reports to its observers.
func (f *knownFixture) signIn(userID, device string, remember bool) *domain.Session {
	sess := &domain.Session{ID: "sess-" + userID, RealmID: realmA, UserID: userID, RememberMe: remember,
		DeviceFingerprint: service.DeviceFingerprint(device), Status: domain.SessionActive}
	f.accounts.SessionCreated(context.Background(), sess)
	f.now = f.now.Add(time.Minute)
	return sess
}

func (f *knownFixture) list(t *testing.T, device string, current *domain.Session) []core.Account {
	t.Helper()
	out, err := f.accounts.List(context.Background(), core.AccountQuery{RealmID: realmA, DeviceID: device, Current: current})
	require.NoError(t, err)
	return out
}

func names(accounts []core.Account) []string {
	out := make([]string, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, a.Name)
	}
	return out
}

func TestKnownAccounts_Remember(t *testing.T) {
	t.Run("only a sign-in with Keep me signed in remembers the account", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, false)
		require.Empty(t, f.list(t, deviceA, nil))
		f.signIn(aliceID, deviceA, true)
		require.Equal(t, []string{"Alice Martin"}, names(f.list(t, deviceA, nil)))
	})

	t.Run("a sign-in without the box removes nothing", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		f.signIn(aliceID, deviceA, false)
		require.Len(t, f.list(t, deviceA, nil), 1)
	})

	t.Run("per device: another browser sees nothing", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		require.Empty(t, f.list(t, deviceB, nil))
		require.Empty(t, f.list(t, "", nil), "no device cookie")
		require.Empty(t, f.list(t, "not-a-device-id", nil), "malformed cookie")
	})

	t.Run("most recently used first", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		f.signIn(bobID, deviceA, true)
		require.Equal(t, []string{"bob", "Alice Martin"}, names(f.list(t, deviceA, nil)))
		f.signIn(aliceID, deviceA, true)
		require.Equal(t, []string{"Alice Martin", "bob"}, names(f.list(t, deviceA, nil)))
	})

	t.Run("at most 10 per device: the least recently used goes", func(t *testing.T) {
		f := newKnownFixture()
		for i := 0; i < service.MaxKnownAccountsPerDevice+2; i++ {
			id := fmt.Sprintf("user-%02d", i)
			f.users.byID[id] = &domain.User{ID: id, RealmID: realmA, Username: id, Status: domain.UserActive}
			f.signIn(id, deviceA, true)
		}
		got := names(f.list(t, deviceA, nil))
		require.Len(t, got, service.MaxKnownAccountsPerDevice)
		require.Equal(t, "user-11", got[0])
		require.NotContains(t, got, "user-00")
		require.NotContains(t, got, "user-01")
	})
}

func TestKnownAccounts_List(t *testing.T) {
	t.Run("tiles: name, e-mail, identifier", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		f.signIn(bobID, deviceA, true)
		got := f.list(t, deviceA, nil)
		require.Equal(t, core.Account{ID: got[1].ID, Name: "Alice Martin", Email: "alice@example.com", Username: "alice",
			Identifier: "alice@example.com", Methods: []core.SignInMethod{core.SignInPassword}}, got[1])
		require.Equal(t, "bob", got[0].Identifier, "no e-mail: the username")
		require.NotEmpty(t, got[0].ID)
	})

	t.Run("the current session comes first, signed in, even when not remembered", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		current := f.signIn(bobID, deviceA, false)
		got := f.list(t, deviceA, current)
		require.Equal(t, []string{"bob", "Alice Martin"}, names(got))
		require.True(t, got[0].SignedIn)
		require.Empty(t, got[0].ID, "bob is not remembered: no Forget")
		require.False(t, got[1].SignedIn)
	})

	t.Run("a remembered current account shows once, with its id", func(t *testing.T) {
		f := newKnownFixture()
		current := f.signIn(aliceID, deviceA, true)
		got := f.list(t, deviceA, current)
		require.Len(t, got, 1)
		require.True(t, got[0].SignedIn)
		require.NotEmpty(t, got[0].ID)
	})

	t.Run("suspended, deleted or other-realm accounts are hidden", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		f.signIn(bobID, deviceA, true)
		f.users.byID[bobID].Status = domain.UserSuspended
		require.Equal(t, []string{"Alice Martin"}, names(f.list(t, deviceA, nil)))
		delete(f.users.byID, aliceID)
		require.Empty(t, f.list(t, deviceA, nil))

		f.users.byID["user-other"] = &domain.User{ID: "user-other", RealmID: "realm-b", Username: "eve", Status: domain.UserActive}
		f.signIn("user-other", deviceA, true) // recorded under realmA by the fixture...
		require.Empty(t, f.list(t, deviceA, nil), "...but the user belongs to another realm")
	})
}

func TestKnownAccounts_Forget(t *testing.T) {
	ctx := context.Background()

	t.Run("removes the tile and audits it", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		id := f.list(t, deviceA, nil)[0].ID

		row, err := f.accounts.Forget(ctx, service.ForgetAccountInput{RealmID: realmA, DeviceID: deviceA, AccountID: id, IPAddress: "203.0.113.9"})
		require.NoError(t, err)
		require.Equal(t, aliceID, row.UserID)
		require.Empty(t, f.list(t, deviceA, nil))
		require.Len(t, f.audit.entries, 1)
		require.Equal(t, "known_account.forget", f.audit.entries[0].Action)
		require.Equal(t, aliceID, f.audit.entries[0].UserID)
	})

	t.Run("only from the device that shows it", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		id := f.list(t, deviceA, nil)[0].ID

		for _, in := range []service.ForgetAccountInput{
			{RealmID: realmA, DeviceID: deviceB, AccountID: id},
			{RealmID: realmA, DeviceID: "", AccountID: id},
			{RealmID: "realm-b", DeviceID: deviceA, AccountID: id},
			{RealmID: realmA, DeviceID: deviceA, AccountID: "unknown"},
		} {
			_, err := f.accounts.Forget(ctx, in)
			require.ErrorIs(t, err, service.ErrKnownAccountNotFound, "%+v", in)
		}
		require.Len(t, f.list(t, deviceA, nil), 1, "still there")
		require.Empty(t, f.audit.entries)
	})

	t.Run("signing in again with the box brings it back", func(t *testing.T) {
		f := newKnownFixture()
		f.signIn(aliceID, deviceA, true)
		_, err := f.accounts.Forget(ctx, service.ForgetAccountInput{RealmID: realmA, DeviceID: deviceA, AccountID: f.list(t, deviceA, nil)[0].ID})
		require.NoError(t, err)
		f.signIn(aliceID, deviceA, true)
		require.Len(t, f.list(t, deviceA, nil), 1)
	})
}

func TestSessionService_LogoutIsAudited(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	audit := &fakeAuditRepo{}
	repo := &fakeSessionRepo{now: func() time.Time { return now }, byID: map[string]*domain.Session{}}
	svc := service.NewSessionService(repo, fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		fakeSessionCache{}, service.WithClock(func() time.Time { return now }), service.WithAuditLog(audit))

	raw, sess, err := svc.Create(ctx, service.CreateSessionInput{RealmID: realmA, UserID: aliceID, RememberMe: true})
	require.NoError(t, err)
	require.NoError(t, svc.Logout(ctx, raw, service.LogoutEvent{Via: domain.LogoutViaAPI, IPAddress: "203.0.113.9", UserAgent: "test"}))

	require.Len(t, audit.entries, 1)
	e := audit.entries[0]
	require.Equal(t, "logout", e.Action)
	require.Equal(t, "Session", e.ResourceType)
	require.Equal(t, sess.ID, e.ResourceID)
	require.Equal(t, aliceID, e.UserID)
	require.Equal(t, "203.0.113.9", e.IPAddress)
	require.Equal(t, map[string]interface{}{"via": "auth_api", "remember_me": true}, e.Details)

	// Signing out of a session that is already over writes nothing more.
	require.NoError(t, svc.Logout(ctx, raw, service.LogoutEvent{Via: domain.LogoutViaAPI}))
	require.Len(t, audit.entries, 1)

	// Another account signing in: revoked with its own reason and channel.
	_, other, err := svc.Create(ctx, service.CreateSessionInput{RealmID: realmA, UserID: bobID})
	require.NoError(t, err)
	require.NoError(t, svc.EndSession(ctx, other, domain.SessionRevokedAccountSwitch, service.LogoutEvent{
		Via: domain.LogoutViaAccountSwitch, ClientID: "webapp", Confirmed: true,
	}))
	require.Equal(t, domain.SessionRevokedAccountSwitch, repo.byID[other.ID].RevokedReason)
	require.Equal(t, map[string]interface{}{"via": "account_switch", "remember_me": false, "client_id": "webapp", "confirmed": true},
		audit.entries[1].Details)
}
