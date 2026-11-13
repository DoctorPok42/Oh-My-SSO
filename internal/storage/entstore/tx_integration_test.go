package entstore_test

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/ent"
	"sso.internal/sso/ent/clientrole"
	entgroup "sso.internal/sso/ent/group"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/storage/entstore"
)

// newTxFixture: a client on the transactional driver, as app.BuildCore
// wires it, and a realm.
func newTxFixture(t *testing.T) (*rbacFixture, *entstore.Driver) {
	t.Helper()
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	drv := entstore.NewDriver(db)
	client := ent.NewClient(ent.Driver(drv))
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	return &rbacFixture{t: t, ctx: ctx, client: client, realm: newTestRealm(t, ctx, client)}, drv
}

func (f *rbacFixture) createUser(ctx context.Context, name string) (*domain.User, error) {
	return entstore.NewUserRepository(f.client).Create(ctx, repository.CreateUserParams{
		RealmID: f.realm.ID, Username: name, Email: name + "@example.test", Status: domain.UserActive,
	})
}

func (f *rbacFixture) userExists(name string) bool {
	f.t.Helper()
	_, err := entstore.NewUserRepository(f.client).GetByRealmAndUsername(f.ctx, f.realm.ID, name)
	if errors.Is(err, repository.ErrNotFound) {
		return false
	}
	require.NoError(f.t, err)
	return true
}

var errInjected = errors.New("injected failure")

func TestDriver_InTx_CommitsOrRollsBack_Integration(t *testing.T) {
	f, drv := newTxFixture(t)

	require.NoError(t, drv.InTx(f.ctx, func(ctx context.Context) error {
		_, err := f.createUser(ctx, "kept")
		return err
	}))
	require.True(t, f.userExists("kept"), "committed when fn returns nil")

	err := drv.InTx(f.ctx, func(ctx context.Context) error {
		_, err := f.createUser(ctx, "dropped")
		require.NoError(t, err)
		return errInjected
	})
	require.ErrorIs(t, err, errInjected, "fn's error is returned as is")
	require.False(t, f.userExists("dropped"), "rolled back when fn fails")

	require.PanicsWithValue(t, "boom", func() {
		_ = drv.InTx(f.ctx, func(ctx context.Context) error {
			_, err := f.createUser(ctx, "panicked")
			require.NoError(t, err)
			panic("boom")
		})
	})
	require.False(t, f.userExists("panicked"), "rolled back on panic")
}

func TestDriver_InTx_InvisibleUntilCommitted_Integration(t *testing.T) {
	f, drv := newTxFixture(t)
	users := entstore.NewUserRepository(f.client)

	require.NoError(t, drv.InTx(f.ctx, func(ctx context.Context) error {
		u, err := f.createUser(ctx, "pending")
		require.NoError(t, err)
		_, err = users.GetByID(ctx, u.ID)
		require.NoError(t, err, "visible inside the transaction")
		_, err = users.GetByID(f.ctx, u.ID)
		require.ErrorIs(t, err, repository.ErrNotFound, "a context without the transaction does not see it yet")
		return nil
	}))
	require.True(t, f.userExists("pending"))
}

// The transactions ent opens itself (an UpdateOne that changes edges,
// withTx of the admin repository) join the one of InTx: rolled back with it.
func TestDriver_InTx_EntTransactionsJoin_Integration(t *testing.T) {
	f, drv := newTxFixture(t)
	admin := entstore.NewAdminRepository(f.client)
	group, role, app := f.group(), f.role(), f.clientApp("joined")

	err := drv.InTx(f.ctx, func(ctx context.Context) error {
		u, err := f.createUser(ctx, "joined")
		require.NoError(t, err)
		require.NoError(t, admin.SetUserGroups(ctx, u.ID, []string{group.ID}))       // sqlgraph.UpdateNode: drv.Tx
		require.NoError(t, admin.SetClientRoles(ctx, app.ID, []string{role.ID}, "")) // withTx: client.Tx
		return errInjected
	})
	require.ErrorIs(t, err, errInjected)
	require.False(t, f.userExists("joined"))
	n, err := f.client.ClientRole.Query().Where(clientrole.ClientAppID(app.ID)).Count(f.ctx)
	require.NoError(t, err)
	require.Zero(t, n, "withTx did not commit on its own")

	// Committed together otherwise.
	require.NoError(t, drv.InTx(f.ctx, func(ctx context.Context) error {
		return admin.SetClientRoles(ctx, app.ID, []string{role.ID}, "")
	}))
	n, err = f.client.ClientRole.Query().Where(clientrole.ClientAppID(app.ID)).Count(f.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

func TestDriver_InTx_NestedJoinsTheOuter_Integration(t *testing.T) {
	f, drv := newTxFixture(t)

	err := drv.InTx(f.ctx, func(ctx context.Context) error {
		require.NoError(t, drv.InTx(ctx, func(ctx context.Context) error {
			_, err := f.createUser(ctx, "inner")
			return err
		}))
		return errInjected
	})
	require.ErrorIs(t, err, errInjected)
	require.False(t, f.userExists("inner"), "the inner InTx did not commit on its own")
}

// R-03 (lot B): a context kept after its InTx (a goroutine started inside)
// carries an ended transaction: its queries run on their own, and an InTx
// with it opens a new transaction instead of using the ended one.
func TestDriver_InTx_KeptContextAfterTheEnd_Integration(t *testing.T) {
	f, drv := newTxFixture(t)

	var kept context.Context
	var id string
	require.NoError(t, drv.InTx(f.ctx, func(ctx context.Context) error {
		u, err := f.createUser(ctx, "outlived")
		kept, id = ctx, u.ID
		return err
	}))
	_, err := entstore.NewUserRepository(f.client).GetByID(kept, id)
	require.NoError(t, err, "runs on its own and sees what was committed")

	err = drv.InTx(kept, func(ctx context.Context) error {
		_, err := f.createUser(ctx, "second")
		require.NoError(t, err)
		return errInjected
	})
	require.ErrorIs(t, err, errInjected)
	require.False(t, f.userExists("second"), "a new transaction, rolled back")

	require.NoError(t, drv.InTx(kept, func(ctx context.Context) error {
		_, err := f.createUser(ctx, "third")
		return err
	}))
	require.True(t, f.userExists("third"), "a new transaction, committed")
}

// R-03 (lot B): a transaction ended by runtime.Goexit (t.FailNow in a
// test) is rolled back, and its connection goes back to the pool.
func TestDriver_InTx_GoexitRollsBack_Integration(t *testing.T) {
	f, _ := newTxFixture(t)
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	drv := entstore.NewDriver(db)
	t.Cleanup(func() { _ = drv.Close() })
	users := entstore.NewUserRepository(ent.NewClient(ent.Driver(drv)))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = drv.InTx(f.ctx, func(ctx context.Context) error {
			_, err := users.Create(ctx, repository.CreateUserParams{
				RealmID: f.realm.ID, Username: "goexit", Email: "goexit@example.test", Status: domain.UserActive,
			})
			require.NoError(t, err)
			runtime.Goexit()
			return nil
		})
	}()
	<-done
	require.False(t, f.userExists("goexit"), "rolled back")
	require.Zero(t, db.Stats().InUse, "no connection left open")
}

// The transaction of one driver is never used by the client of another.
func TestDriver_InTx_OtherDriverIgnoresIt_Integration(t *testing.T) {
	f, _ := newTxFixture(t)
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err)
	other := entstore.NewDriver(db)
	t.Cleanup(func() { _ = other.Close() })

	err = other.InTx(f.ctx, func(ctx context.Context) error {
		_, err := f.createUser(ctx, "elsewhere") // f's client: not in other's transaction
		require.NoError(t, err)
		return errInjected
	})
	require.ErrorIs(t, err, errInjected)
	require.True(t, f.userExists("elsewhere"))
}

// failingTokens fails Revoke while fail is set: the revocation of the
// sessions breaks in the middle of a transaction.
type failingTokens struct {
	repository.TokenRepository
	mu   sync.Mutex
	fail bool
}

func (r *failingTokens) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	fail := r.fail
	r.mu.Unlock()
	if fail {
		return errInjected
	}
	return r.TokenRepository.Revoke(ctx, id)
}

func (r *failingTokens) set(fail bool) {
	r.mu.Lock()
	r.fail = fail
	r.mu.Unlock()
}

type lastEventNotifier struct {
	mu     sync.Mutex
	events []domain.NotificationEvent
}

func (n *lastEventNotifier) Notify(_ context.Context, e domain.NotificationEvent) {
	n.mu.Lock()
	n.events = append(n.events, e)
	n.mu.Unlock()
}

func (n *lastEventNotifier) last() domain.NotificationEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.events[len(n.events)-1]
}

// signedIn gives u a session with an access token issued for an application.
func (f *rbacFixture) signedIn(u *domain.User) (*domain.Session, *domain.Token) {
	f.t.Helper()
	sess, err := entstore.NewSessionRepository(f.client).Create(f.ctx, repository.CreateSessionParams{
		RealmID: f.realm.ID, UserID: u.ID, TokenHash: "hash-" + f.suffix(),
		ExpiresAt: time.Now().Add(time.Hour), AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(f.t, err)
	tok, err := entstore.NewTokenRepository(f.client).Create(f.ctx, repository.CreateTokenParams{
		SessionID: sess.ID, ClientRefID: f.clientApp("app").ID, Type: domain.TokenAccessToken,
		JTI: "jti-" + f.suffix(), ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(f.t, err)
	return sess, tok
}

func (f *rbacFixture) requireSignedIn(sess *domain.Session, tok *domain.Token, want bool) {
	f.t.Helper()
	got, err := entstore.NewSessionRepository(f.client).GetByID(f.ctx, sess.ID)
	require.NoError(f.t, err)
	gotTok, err := entstore.NewTokenRepository(f.client).GetByJTI(f.ctx, tok.JTI)
	require.NoError(f.t, err)
	if want {
		require.Equal(f.t, domain.SessionActive, got.Status, "session still active")
		require.False(f.t, gotTok.Revoked, "token still valid")
	} else {
		require.Equal(f.t, domain.SessionRevoked, got.Status, "session revoked")
		require.True(f.t, gotTok.Revoked, "token revoked with its session")
	}
}

func (f *rbacFixture) sessionService(tokens repository.TokenRepository) *service.SessionService {
	return service.NewSessionService(entstore.NewSessionRepository(f.client),
		entstore.NewInstanceSettingsRepository(f.client), tokens, noopSessionCache{})
}

// B-06: a reset that fails half-way writes nothing, and its link still works.
func TestPasswordReset_IsOneTransaction_Integration(t *testing.T) {
	f, drv := newTxFixture(t)
	users := entstore.NewUserRepository(f.client)
	oldHash, err := service.HashPasswordContext(f.ctx, "the old passphrase")
	require.NoError(t, err)
	u, err := users.Create(f.ctx, repository.CreateUserParams{
		RealmID: f.realm.ID, Username: "carol", Email: "carol@example.test", PasswordHash: oldHash, Status: domain.UserActive,
	})
	require.NoError(t, err)
	mustChange := true // a forced reset in progress: the reset ends it
	_, err = users.Update(f.ctx, u.ID, repository.UpdateUserParams{MustChangePassword: &mustChange})
	require.NoError(t, err)
	sess, tok := f.signedIn(u)

	tokens := &failingTokens{TokenRepository: entstore.NewTokenRepository(f.client), fail: true}
	notifier := &lastEventNotifier{}
	settings := entstore.NewInstanceSettingsRepository(f.client)
	reset := service.NewPasswordResetService(service.PasswordResetDeps{
		Tx: drv, Users: users, Tokens: entstore.NewPasswordResetTokenRepository(f.client),
		Sessions: f.sessionService(tokens), Settings: settings, Notifier: notifier,
	})
	require.NoError(t, reset.RequestReset(f.ctx, service.RequestResetInput{RealmID: f.realm.ID, Identifier: "carol"}))
	link := notifier.last().ResetToken
	in := service.ResetPasswordInput{RealmID: f.realm.ID, Token: link, NewPassword: "a brand new passphrase"}

	err = reset.ResetPassword(f.ctx, in)
	require.ErrorIs(t, err, errInjected)
	got, err := users.GetByID(f.ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, oldHash, got.PasswordHash, "password unchanged")
	require.True(t, got.MustChangePassword, "forced reset still pending")
	f.requireSignedIn(sess, tok, true)
	require.Equal(t, domain.NotificationPasswordReset, notifier.last().Kind, "no \"password changed\" e-mail")

	tokens.set(false)
	require.NoError(t, reset.ResetPassword(f.ctx, in), "the same link works again")
	got, err = users.GetByID(f.ctx, u.ID)
	require.NoError(t, err)
	require.NotEqual(t, oldHash, got.PasswordHash)
	require.False(t, got.MustChangePassword)
	f.requireSignedIn(sess, tok, false)
	require.Equal(t, domain.NotificationPasswordChanged, notifier.last().Kind)
	require.ErrorIs(t, reset.ResetPassword(f.ctx, in), service.ErrResetTokenInvalid, "used up now")
}

// failingAdmin fails SetUserRoles / SetUserProfile: the creation or the
// change of an account breaks after its first write.
type failingAdmin struct {
	repository.AdminRepository
	failRoles, failProfile bool
}

func (r failingAdmin) SetUserRoles(ctx context.Context, userID string, roleIDs []string) error {
	if r.failRoles {
		return errInjected
	}
	return r.AdminRepository.SetUserRoles(ctx, userID, roleIDs)
}

func (r failingAdmin) SetUserProfile(ctx context.Context, userID string, profile map[string]interface{}) error {
	if r.failProfile {
		return errInjected
	}
	return r.AdminRepository.SetUserProfile(ctx, userID, profile)
}

// adminService: what InviteUser and UpdateUser use (no e-mail).
func (f *rbacFixture) adminService(tx repository.Transactor, admin repository.AdminRepository, sessions *service.SessionService) *service.AdminService {
	users := entstore.NewUserRepository(f.client)
	settings := entstore.NewInstanceSettingsRepository(f.client)
	return service.NewAdminService(service.AdminDeps{
		Tx: tx, Users: users, Groups: entstore.NewGroupRepository(f.client), Roles: entstore.NewRoleRepository(f.client),
		Admin: admin, Sessions: sessions, Settings: settings, Access: entstore.NewAccessRepository(f.client),
		MFA: service.NewMFAService(service.MFADeps{
			Methods: entstore.NewMfaMethodRepository(f.client), BackupCodes: entstore.NewMfaBackupCodeRepository(f.client),
		}),
		PasswordReset: service.NewPasswordResetService(service.PasswordResetDeps{
			Tx: tx, Users: users, Tokens: entstore.NewPasswordResetTokenRepository(f.client), Settings: settings,
		}),
		PublicURL: "https://sso.example.test",
	})
}

// B-15: an invitation that fails half-way leaves no account, so that the
// retry does not stumble on its own username.
func TestAdminInviteUser_IsOneTransaction_Integration(t *testing.T) {
	f, drv := newTxFixture(t)
	group, role := f.group(), f.role()
	admin := f.adminService(drv, failingAdmin{AdminRepository: entstore.NewAdminRepository(f.client), failRoles: true}, nil)
	in := service.InviteUserInput{Username: "dave", Email: "dave@example.test", GroupIDs: []string{group.ID}, RoleIDs: []string{role.ID},
		Profile: map[string]interface{}{"team": "ops"}}

	for range 2 {
		_, err := admin.InviteUser(f.ctx, service.AdminActor{}, f.realm, in)
		require.ErrorIs(t, err, errInjected, "the injected failure, not \"username taken\"")
		require.False(t, f.userExists("dave"), "no account left behind")
	}
	n, err := f.client.Group.Query().Where(entgroup.ID(group.ID)).QueryUsers().Count(f.ctx)
	require.NoError(t, err)
	require.Zero(t, n, "no membership left behind")

	admin = f.adminService(drv, entstore.NewAdminRepository(f.client), nil)
	res, err := admin.InviteUser(f.ctx, service.AdminActor{}, f.realm, in)
	require.NoError(t, err, "the retry goes through")
	require.Len(t, res.User.Groups, 1)
	require.Len(t, res.User.Roles, 1)
	require.Equal(t, "ops", res.User.Profile["team"])
	require.NotEmpty(t, res.ActivationURL)
}

// B-15: a suspension whose sign-out fails leaves the account active, with
// its sessions; a change of profile that fails leaves the status as it was.
func TestAdminUpdateUser_IsOneTransaction_Integration(t *testing.T) {
	f, drv := newTxFixture(t)
	u := f.user()
	sess, tok := f.signedIn(u)
	tokens := &failingTokens{TokenRepository: entstore.NewTokenRepository(f.client), fail: true}
	repo := entstore.NewAdminRepository(f.client)
	suspended := domain.UserSuspended
	users := entstore.NewUserRepository(f.client)

	admin := f.adminService(drv, repo, f.sessionService(tokens))
	_, err := admin.UpdateUser(f.ctx, service.AdminActor{}, f.realm, u.ID, service.UpdateUserInput{Status: &suspended})
	require.ErrorIs(t, err, errInjected)
	got, err := users.GetByID(f.ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, domain.UserActive, got.Status, "not suspended")
	f.requireSignedIn(sess, tok, true)

	admin = f.adminService(drv, failingAdmin{AdminRepository: repo, failProfile: true}, f.sessionService(entstore.NewTokenRepository(f.client)))
	_, err = admin.UpdateUser(f.ctx, service.AdminActor{}, f.realm, u.ID, service.UpdateUserInput{
		Status: &suspended, Profile: map[string]interface{}{"team": "ops"},
	})
	require.ErrorIs(t, err, errInjected)
	got, err = users.GetByID(f.ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, domain.UserActive, got.Status, "not suspended")
	f.requireSignedIn(sess, tok, true)

	// Nothing fails in the database; the session cache does not answer
	// after the commit: the suspension is done all the same, and the
	// observers (trusted devices) are told.
	observer := &revocationRecorder{}
	sessions := service.NewSessionService(entstore.NewSessionRepository(f.client), entstore.NewInstanceSettingsRepository(f.client),
		entstore.NewTokenRepository(f.client), brokenCache{}, service.WithRevocationObserver(observer))
	admin = f.adminService(drv, repo, sessions)
	view, err := admin.UpdateUser(f.ctx, service.AdminActor{}, f.realm, u.ID, service.UpdateUserInput{
		Status: &suspended, Profile: map[string]interface{}{"team": "ops"},
	})
	require.NoError(t, err, "the cache is told at best")
	require.Equal(t, domain.UserSuspended, view.Status)
	require.Equal(t, "ops", view.Profile["team"])
	f.requireSignedIn(sess, tok, false)
	require.Equal(t, []string{u.ID}, observer.users())
}

// brokenCache: Valkey does not answer the tombstones.
type brokenCache struct{ noopSessionCache }

func (brokenCache) MarkRevoked(context.Context, string, time.Duration) error {
	return errors.New("valkey: connection refused")
}

type revocationRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (r *revocationRecorder) AllSessionsRevoked(_ context.Context, userID string, _ domain.SessionRevokedReason) {
	r.mu.Lock()
	r.ids = append(r.ids, userID)
	r.mu.Unlock()
}

func (r *revocationRecorder) users() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}
