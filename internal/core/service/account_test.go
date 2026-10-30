package service_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/memstore"
)

const acctRealm = "realm-acct"

// acctSessions is fakeSessionRepo with the live-session list RevokeOthers
// needs.
type acctSessions struct{ *fakeSessionRepo }

func (s acctSessions) ListActiveByUser(_ context.Context, userID string) ([]*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.Session
	for _, se := range s.byID {
		if se.UserID == userID && se.Status == domain.SessionActive {
			cp := *se
			out = append(out, &cp)
		}
	}
	return out, nil
}

// acctAdmin: the parts of AdminRepository the account console uses.
type acctAdmin struct {
	repository.AdminRepository
	users    *memUsers
	sessions *fakeSessionRepo
	tokens   *fakeTokenRepo
	audit    []*domain.AuditLog // what SearchAuditLogs answers
	searched repository.AuditSearch
}

func (a *acctAdmin) SetUserProfile(_ context.Context, userID string, profile map[string]interface{}) error {
	a.users.mu.Lock()
	defer a.users.mu.Unlock()
	a.users.byID[userID].Profile = profile
	return nil
}

func (a *acctAdmin) SearchSessions(_ context.Context, f repository.SessionSearch) ([]*domain.Session, int, error) {
	a.sessions.mu.Lock()
	defer a.sessions.mu.Unlock()
	var out []*domain.Session
	for _, se := range a.sessions.byID {
		if se.RealmID == f.RealmID && se.UserID == f.UserID && se.Status == domain.SessionActive &&
			se.ExpiresAt.After(f.Now) && !se.LastActivityAt.Before(f.IdleSince) {
			cp := *se
			out = append(out, &cp)
		}
	}
	return out, len(out), nil
}

func (a *acctAdmin) SessionClients(_ context.Context, ids []string, _ time.Time) (map[string][]string, error) {
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	out := map[string][]string{}
	for _, t := range a.tokens.byJTI {
		for _, id := range ids {
			if t.SessionID == id && !t.Revoked {
				out[id] = append(out[id], t.ClientRefID)
			}
		}
	}
	return out, nil
}

func (a *acctAdmin) SearchAuditLogs(_ context.Context, f repository.AuditSearch) ([]*domain.AuditLog, int, error) {
	a.searched = f
	rows := a.audit
	if f.Offset < len(rows) {
		rows = rows[f.Offset:]
	} else {
		rows = nil
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		rows = rows[:f.Limit]
	}
	return rows, -1, nil
}

// acctAttempts answers ListByUser from a fixed list, newest first.
type acctAttempts struct {
	repository.LoginAttemptRepository
	rows []*domain.LoginAttempt
}

func (a *acctAttempts) ListByUser(_ context.Context, userID string, p repository.Page) ([]*domain.LoginAttempt, error) {
	var mine []*domain.LoginAttempt
	for _, r := range a.rows {
		if r.UserID == userID {
			mine = append(mine, r)
		}
	}
	if p.Offset >= len(mine) {
		return nil, nil
	}
	mine = mine[p.Offset:]
	if len(mine) > p.Limit {
		mine = mine[:p.Limit]
	}
	return mine, nil
}

type acctScopes struct {
	repository.ClientScopeRepository
}

func (acctScopes) GetByRealmAndName(_ context.Context, realmID, name string) (*domain.ClientScope, error) {
	if realmID == acctRealm && name == "payroll.read" {
		return &domain.ClientScope{Name: name, Description: "Read your payslips"}, nil
	}
	return nil, repository.ErrNotFound
}

type acctFixture struct {
	clock    *testClock
	users    *memUsers
	sessions *fakeSessionRepo
	sessSvc  *service.SessionService
	tokens   *fakeTokenRepo
	consents *fakeConsentRepo
	clients  *fakeClientAppRepo
	admin    *acctAdmin
	attempts *acctAttempts
	devices  *memstore.TrustedDevices
	audit    *fakeAuditRepo
	notifier *recordingNotifier
	svc      *service.AccountService
	user     *domain.User
	other    *domain.User // another user of the same realm
}

func newAcctFixture(t *testing.T) *acctFixture {
	t.Helper()
	f := &acctFixture{clock: newTestClock(), audit: &fakeAuditRepo{}, notifier: &recordingNotifier{}}
	f.user = &domain.User{ID: "u-dana", RealmID: acctRealm, Username: "dana", Email: "dana@example.test",
		PasswordHash: alicePasswordHash(t), Status: domain.UserActive,
		Profile: map[string]interface{}{"locale": "fr"}}
	f.other = &domain.User{ID: "u-eve", RealmID: acctRealm, Username: "eve", Email: "eve@example.test", Status: domain.UserActive}
	f.users = newMemUsers(f.user, f.other)
	f.sessions = &fakeSessionRepo{now: f.clock.Now, byID: map[string]*domain.Session{}}
	f.tokens = &fakeTokenRepo{byJTI: map[string]*domain.Token{}, sessionUser: func(sid string) string {
		f.sessions.mu.Lock()
		defer f.sessions.mu.Unlock()
		if se, ok := f.sessions.byID[sid]; ok {
			return se.UserID
		}
		return ""
	}}
	f.sessSvc = service.NewSessionService(acctSessions{f.sessions}, fakeSettingsRepo{}, f.tokens, fakeSessionCache{},
		service.WithClock(f.clock.Now))
	f.consents = newFakeConsentRepo(f.clock.Now)
	f.clients = &fakeClientAppRepo{byID: map[string]*domain.ClientApp{
		"c-payroll": {ID: "c-payroll", RealmID: acctRealm, Name: "Payroll", Protocol: domain.ClientAppProtocolOIDC,
			Status: domain.ClientAppActive, RedirectURIs: []string{"https://payroll.example.test/callback"}},
		"c-wiki": {ID: "c-wiki", RealmID: acctRealm, Name: "Wiki", Protocol: domain.ClientAppProtocolSAML2,
			Status: domain.ClientAppActive, ACSURL: "https://wiki.example.test/saml/acs"},
		"c-foreign": {ID: "c-foreign", RealmID: "realm-other", Name: "Foreign", Protocol: domain.ClientAppProtocolOIDC,
			Status: domain.ClientAppActive},
	}}
	f.admin = &acctAdmin{users: f.users, sessions: f.sessions, tokens: f.tokens}
	f.attempts = &acctAttempts{}
	f.devices = memstore.NewTrustedDevices()
	f.svc = service.NewAccountService(service.AccountDeps{
		Users: f.users, Admin: f.admin, Settings: fakeSettingsRepo{}, Clients: f.clients, ClientScopes: acctScopes{},
		Tokens: f.tokens, LoginAttempts: f.attempts, Audit: f.audit,
		Sessions: f.sessSvc,
		Consents: service.NewConsentService(service.ConsentDeps{
			Consents: f.consents, Clients: f.clients, Tokens: f.tokens, Audit: f.audit,
		}),
		TrustedDevices: service.NewTrustedDeviceService(service.TrustedDeviceDeps{Devices: f.devices, Now: f.clock.Now}),
		Policy:         service.NewPasswordPolicyService(nil),
		Notifier:       f.notifier,
		Now:            f.clock.Now,
	})
	return f
}

func (f *acctFixture) session(t *testing.T, user *domain.User) *domain.Session {
	t.Helper()
	_, sess, err := f.sessSvc.Create(context.Background(), service.CreateSessionInput{
		RealmID: user.RealmID, UserID: user.ID, IPAddress: "198.51.100.7", UserAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0",
		AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(t, err)
	return sess
}

func (f *acctFixture) token(sessionID, clientRef string) {
	f.tokens.mu.Lock()
	defer f.tokens.mu.Unlock()
	jti := fmt.Sprintf("jti-%d", len(f.tokens.byJTI)+1)
	f.tokens.byJTI[jti] = &domain.Token{ID: "t-" + jti, JTI: jti, SessionID: sessionID, ClientRefID: clientRef,
		Type: domain.TokenAccessToken, ExpiresAt: f.clock.Now().Add(time.Hour)}
}

func (f *acctFixture) actions() []string {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	out := []string{}
	for _, e := range f.audit.entries {
		out = append(out, e.Action+":"+string(e.Status))
	}
	return out
}

var ev = service.AccountEvent{IPAddress: "198.51.100.7", UserAgent: "test"}

func TestAccount_UpdateName(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()

	u, err := f.svc.UpdateName(ctx, f.user, service.NameInput{GivenName: "  Dana ", FamilyName: "Scully  Fox"}, ev)
	require.NoError(t, err)
	stored := f.users.get(f.user.ID)
	require.Equal(t, "Dana", stored.Profile["given_name"])
	require.Equal(t, "Scully Fox", stored.Profile["family_name"], "inner spaces are folded")
	require.Equal(t, "Dana Scully Fox", stored.Profile["name"])
	require.Equal(t, "fr", stored.Profile["locale"], "the other profile keys stay")
	require.Equal(t, stored.Profile, u.Profile)
	require.Equal(t, []string{"account.profile_updated:success"}, f.actions())

	_, err = f.svc.UpdateName(ctx, u, service.NameInput{GivenName: "Dana", FamilyName: "Scully Fox"}, ev)
	require.NoError(t, err)
	require.Len(t, f.actions(), 1, "no change, no audit entry")

	u, err = f.svc.UpdateName(ctx, u, service.NameInput{GivenName: "Dana"}, ev)
	require.NoError(t, err)
	require.NotContains(t, u.Profile, "family_name", "an empty value removes the key")
	require.Equal(t, "Dana", u.Profile["name"])

	for _, bad := range []string{strings.Repeat("a", 101), "Dana\x00", "Da\u0007na"} {
		_, err = f.svc.UpdateName(ctx, u, service.NameInput{GivenName: bad}, ev)
		require.ErrorIs(t, err, service.ErrInvalidName, "%q", bad)
	}
}

func TestAccount_ChangePassword(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	current := f.session(t, f.user)
	otherDevice := f.session(t, f.user)
	f.token(otherDevice.ID, "c-payroll")
	someoneElse := f.session(t, f.other)
	change := func(cur, next string) (*service.ChangePasswordResult, error) {
		return f.svc.ChangePassword(ctx, service.ChangePasswordInput{
			User: f.users.get(f.user.ID), SessionID: current.ID, Current: cur, New: next, Event: ev,
		})
	}

	_, err := change("wrong password", "a-brand-new-passphrase")
	require.ErrorIs(t, err, service.ErrWrongPassword)
	require.Equal(t, []string{"account.password_changed:failure"}, f.actions())

	_, err = change(alicePassword, alicePassword)
	require.ErrorIs(t, err, service.ErrPasswordUnchanged)

	_, err = change(alicePassword, "short")
	require.ErrorIs(t, err, service.ErrPasswordTooShort)

	_, err = change(alicePassword, "dana@example.test")
	require.ErrorIs(t, err, service.ErrPasswordMatchesIdentity)

	res, err := change(alicePassword, "a-brand-new-passphrase")
	require.NoError(t, err)
	require.Equal(t, 1, res.SessionsEnded, "the other session of the user, not the current one")

	auth := service.NewAuthService(f.users, &fakeLoginAttemptRepo{})
	_, err = auth.AuthenticateLocal(ctx, service.AuthenticateLocalParams{RealmID: acctRealm, Identifier: "dana", Password: "a-brand-new-passphrase"})
	require.NoError(t, err, "the new password works")
	_, err = auth.AuthenticateLocal(ctx, service.AuthenticateLocalParams{RealmID: acctRealm, Identifier: "dana", Password: alicePassword})
	require.ErrorIs(t, err, service.ErrInvalidCredentials, "the old one does not")

	sess, _ := f.sessions.GetByID(ctx, current.ID)
	require.Equal(t, domain.SessionActive, sess.Status, "the session in use stays")
	sess, _ = f.sessions.GetByID(ctx, otherDevice.ID)
	require.Equal(t, domain.SessionRevoked, sess.Status)
	require.Equal(t, domain.SessionRevokedPasswordChanged, sess.RevokedReason)
	require.True(t, f.tokens.byJTI["jti-1"].Revoked, "its tokens die with it")
	sess, _ = f.sessions.GetByID(ctx, someoneElse.ID)
	require.Equal(t, domain.SessionActive, sess.Status, "never another user's session")

	require.Contains(t, f.actions(), "account.password_changed:success")
	e := f.notifier.last()
	require.Equal(t, domain.NotificationPasswordChanged, e.Kind)
	require.Equal(t, f.user.ID, e.UserID)
}

func TestAccount_ChangePassword_NoPasswordYet(t *testing.T) {
	f := newAcctFixture(t)
	_, err := f.svc.ChangePassword(context.Background(), service.ChangePasswordInput{
		User: f.other, Current: "", New: "a-brand-new-passphrase",
	})
	require.ErrorIs(t, err, service.ErrNoPassword)
}

// The password changed between the check and the write (a reset link used
// at the same moment): the change is refused, the reset stays.
func TestAccount_ChangePassword_ResetWins(t *testing.T) {
	f := newAcctFixture(t)
	user := f.users.get(f.user.ID)
	f.users.mu.Lock()
	f.users.byID[f.user.ID].PasswordHash = "hash-set-by-a-reset"
	f.users.mu.Unlock()
	_, err := f.svc.ChangePassword(context.Background(), service.ChangePasswordInput{
		User: user, Current: alicePassword, New: "a-brand-new-passphrase",
	})
	require.ErrorIs(t, err, service.ErrWrongPassword)
	require.Equal(t, "hash-set-by-a-reset", f.users.get(f.user.ID).PasswordHash)
}

func TestAccount_Sessions(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	older := f.session(t, f.user)
	f.token(older.ID, "c-payroll")
	f.token(older.ID, "c-wiki")
	f.clock.Advance(time.Minute)
	current := f.session(t, f.user)
	f.session(t, f.other)

	list, err := f.svc.Sessions(ctx, f.users.get(f.user.ID), current.ID)
	require.NoError(t, err)
	require.Len(t, list, 2, "only the user's own sessions")
	require.Equal(t, current.ID, list[0].ID, "the current session first")
	require.True(t, list[0].Current)
	require.Equal(t, older.ID, list[1].ID)
	require.ElementsMatch(t, []string{"Payroll", "Wiki"}, list[1].Apps)
}

func TestAccount_RevokeSession(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	current := f.session(t, f.user)
	other := f.session(t, f.user)
	f.token(other.ID, "c-payroll")
	notMine := f.session(t, f.other)

	require.ErrorIs(t, f.svc.RevokeSession(ctx, user, current.ID, current.ID, ev), service.ErrCurrentSession)
	require.ErrorIs(t, f.svc.RevokeSession(ctx, user, current.ID, notMine.ID, ev), service.ErrSessionNotFound,
		"another user's session is not found, and stays")
	require.ErrorIs(t, f.svc.RevokeSession(ctx, user, current.ID, "no-such-session", ev), service.ErrSessionNotFound)
	sess, _ := f.sessions.GetByID(ctx, notMine.ID)
	require.Equal(t, domain.SessionActive, sess.Status)

	require.NoError(t, f.svc.RevokeSession(ctx, user, current.ID, other.ID, ev))
	sess, _ = f.sessions.GetByID(ctx, other.ID)
	require.Equal(t, domain.SessionRevokedByUser, sess.RevokedReason)
	require.True(t, f.tokens.byJTI["jti-1"].Revoked)
	require.Equal(t, []string{"account.session_revoked:success"}, f.actions())

	require.ErrorIs(t, f.svc.RevokeSession(ctx, user, current.ID, other.ID, ev), service.ErrSessionNotFound, "already signed out")
}

func TestAccount_RevokeOtherSessions(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	current := f.session(t, f.user)
	f.session(t, f.user)
	f.session(t, f.user)
	theirs := f.session(t, f.other)

	n, err := f.svc.RevokeOtherSessions(ctx, f.users.get(f.user.ID), current.ID, ev)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	sess, _ := f.sessions.GetByID(ctx, current.ID)
	require.Equal(t, domain.SessionActive, sess.Status)
	sess, _ = f.sessions.GetByID(ctx, theirs.ID)
	require.Equal(t, domain.SessionActive, sess.Status)
	require.Equal(t, []string{"account.sessions_revoked:success"}, f.actions())
}

func TestAccount_Apps(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	sess := f.session(t, f.user)
	f.consents.rows["consent-1"] = &domain.Consent{ID: "consent-1", UserID: f.user.ID, ClientRefID: "c-payroll",
		Scopes: []string{"openid", "profile", "payroll.read"}, Status: domain.ConsentGranted, GrantedAt: f.clock.Now()}
	f.consents.rows["consent-2"] = &domain.Consent{ID: "consent-2", UserID: f.user.ID, ClientRefID: "c-foreign",
		Scopes: []string{"openid"}, Status: domain.ConsentGranted, GrantedAt: f.clock.Now()}
	f.token(sess.ID, "c-wiki") // a SAML application without consent screen

	apps, err := f.svc.Apps(ctx, user)
	require.NoError(t, err)
	require.Len(t, apps, 2, "never another realm's application")
	require.Equal(t, "Payroll", apps[0].Name)
	require.True(t, apps[0].Consent)
	require.False(t, apps[0].SignedIn)
	require.Equal(t, "payroll.example.test", apps[0].Host)
	require.Equal(t, []service.AppScope{{Name: "profile"}, {Name: "payroll.read", Description: "Read your payslips"}}, apps[0].Scopes,
		"openid is not shown; custom scopes come with their description")
	require.Equal(t, "Wiki", apps[1].Name)
	require.False(t, apps[1].Consent)
	require.True(t, apps[1].SignedIn)
	require.Equal(t, "wiki.example.test", apps[1].Host)
}

func TestAccount_RevokeApp(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	sess := f.session(t, f.user)
	f.consents.rows["consent-1"] = &domain.Consent{ID: "consent-1", UserID: f.user.ID, ClientRefID: "c-payroll",
		Scopes: []string{"openid", "profile"}, Status: domain.ConsentGranted, GrantedAt: f.clock.Now()}
	f.token(sess.ID, "c-payroll")
	f.token(sess.ID, "c-wiki")

	res, err := f.svc.RevokeApp(ctx, user, "c-payroll", ev)
	require.NoError(t, err)
	require.Equal(t, 1, res.TokensRevoked)
	require.Equal(t, domain.ConsentRevoked, f.consents.rows["consent-1"].Status)
	require.Contains(t, f.actions(), "consent_revoked:success")

	res, err = f.svc.RevokeApp(ctx, user, "c-wiki", ev)
	require.NoError(t, err, "no consent screen: its tokens go")
	require.Equal(t, 1, res.TokensRevoked)
	require.Contains(t, f.actions(), "account.app_access_revoked:success")

	_, err = f.svc.RevokeApp(ctx, user, "c-wiki", ev)
	require.ErrorIs(t, err, service.ErrAppNotFound, "nothing left to revoke")
	_, err = f.svc.RevokeApp(ctx, user, "c-foreign", ev)
	require.ErrorIs(t, err, service.ErrAppNotFound, "another realm's application")
	_, err = f.svc.RevokeApp(ctx, user, "no-such-client", ev)
	require.ErrorIs(t, err, service.ErrAppNotFound)
}

func TestAccount_TrustedDevices(t *testing.T) {
	f := newAcctFixture(t)
	ctx := context.Background()
	user := f.users.get(f.user.ID)
	put := func(u *domain.User, hash string) *domain.TrustedDevice {
		d, err := f.devices.Put(ctx, repository.PutTrustedDeviceParams{RealmID: acctRealm, UserID: u.ID, DeviceHash: hash,
			CreatedAt: f.clock.Now(), ExpiresAt: f.clock.Now().Add(24 * time.Hour)})
		require.NoError(t, err)
		return d
	}
	mine := put(f.user, "hash-1")
	put(f.user, "hash-2")
	theirs := put(f.other, "hash-3")

	list, err := f.svc.TrustedDevices(ctx, user)
	require.NoError(t, err)
	require.Len(t, list, 2)

	err = f.svc.RevokeTrustedDevice(ctx, user, theirs.ID, ev)
	require.True(t, errors.Is(err, service.ErrTrustedDeviceNotFound), "another user's device: %v", err)
	require.NoError(t, f.svc.RevokeTrustedDevice(ctx, user, mine.ID, ev))
	n, err := f.svc.RevokeTrustedDevices(ctx, user, ev)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	left, _ := f.devices.ListByUser(ctx, f.other.ID, f.clock.Now())
	require.Len(t, left, 1, "the other user's trust stays")
	require.Equal(t, []string{"account.trusted_device_revoked:success", "account.trusted_devices_revoked:success"}, f.actions())
}

func TestAccount_SignIns(t *testing.T) {
	f := newAcctFixture(t)
	for i := range 5 {
		f.attempts.rows = append(f.attempts.rows, &domain.LoginAttempt{ID: fmt.Sprint(i), RealmID: acctRealm, UserID: f.user.ID,
			IPAddress: "198.51.100.7", Status: domain.LoginAttemptSuccess, CreatedAt: f.clock.Now().Add(-time.Duration(i) * time.Minute)})
	}
	f.attempts.rows = append(f.attempts.rows, &domain.LoginAttempt{ID: "x", RealmID: acctRealm, UserID: f.other.ID})

	page, more, err := f.svc.SignIns(context.Background(), f.user, 0, 3)
	require.NoError(t, err)
	require.Len(t, page, 3)
	require.True(t, more)
	page, more, err = f.svc.SignIns(context.Background(), f.user, 3, 3)
	require.NoError(t, err)
	require.Len(t, page, 2)
	require.False(t, more)
}

func TestAccount_Activity(t *testing.T) {
	f := newAcctFixture(t)
	f.admin.audit = []*domain.AuditLog{
		{Action: "mfa_method_enrolled", UserID: f.user.ID, IPAddress: "198.51.100.7", Details: map[string]interface{}{"type": "totp"}},
		{Action: "admin.user.mfa_reset", UserID: "an-admin-of-master", IPAddress: "10.0.0.9", UserAgent: "admin browser"},
	}
	list, more, err := f.svc.Activity(context.Background(), f.user, 0, 25)
	require.NoError(t, err)
	require.False(t, more)
	require.Len(t, list, 2)
	require.False(t, list[0].ByAdmin)
	require.Equal(t, "198.51.100.7", list[0].IPAddress)
	require.True(t, list[1].ByAdmin)
	require.Empty(t, list[1].IPAddress, "an administrator's address is not shown")
	require.Empty(t, list[1].UserAgent)

	require.Equal(t, acctRealm, f.admin.searched.RealmID)
	require.Equal(t, f.user.ID, f.admin.searched.UserID)
	require.Equal(t, service.AccountActivityActions, f.admin.searched.Actions)
}
