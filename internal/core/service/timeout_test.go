package service_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
)


// fakeTimeoutRepo is the repository in memory, with the same rules as the
// SQL one (in force = not lifted, started, not past its end).
type fakeTimeoutRepo struct {
	mu     sync.Mutex
	seq    int
	byID   map[string]*domain.Timeout
	groups map[string][]string // user id -> group ids
	// failInForce: InForce fails (the database is down).
	failInForce bool
}

func newFakeTimeoutRepo() *fakeTimeoutRepo {
	return &fakeTimeoutRepo{byID: map[string]*domain.Timeout{}, groups: map[string][]string{}}
}

func (f *fakeTimeoutRepo) Create(_ context.Context, p repository.CreateTimeoutParams) (*domain.Timeout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t := &domain.Timeout{ID: fmt.Sprintf("to-%d", f.seq), RealmID: p.RealmID, TargetType: p.TargetType,
		TargetID: p.TargetID, StartsAt: p.StartsAt, EndsAt: p.EndsAt, Reason: p.Reason, CreatedBy: p.CreatedBy,
		CreatedAt: p.StartsAt}
	f.byID[t.ID] = t
	cp := *t
	return &cp, nil
}

func (f *fakeTimeoutRepo) GetByID(_ context.Context, id string) (*domain.Timeout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (f *fakeTimeoutRepo) inForce(t *domain.Timeout, at time.Time) bool {
	return t.LiftedAt.IsZero() && t.InForceAt(at)
}

func (f *fakeTimeoutRepo) ListByRealm(_ context.Context, realmID string, flt repository.TimeoutFilter, page repository.Page) ([]*domain.Timeout, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Timeout
	for _, t := range f.byID {
		if t.RealmID != realmID {
			continue
		}
		current := t.LiftedAt.IsZero() && (t.EndsAt.IsZero() || t.EndsAt.After(flt.At))
		if flt.Current != nil && *flt.Current != current {
			continue
		}
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartsAt.After(out[j].StartsAt) })
	total := len(out)
	if page.Limit > 0 {
		end := min(page.Offset+page.Limit, len(out))
		out = out[min(page.Offset, len(out)):end]
	}
	return out, total, nil
}

func (f *fakeTimeoutRepo) InForce(_ context.Context, userID, clientRef string, at time.Time) ([]*domain.Timeout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failInForce {
		return nil, errors.New("database down")
	}
	var out []*domain.Timeout
	for _, t := range f.byID {
		hit := (userID != "" && t.TargetType == domain.TimeoutTargetUser && t.TargetID == userID) ||
			(userID != "" && t.TargetType == domain.TimeoutTargetGroup && slices.Contains(f.groups[userID], t.TargetID)) ||
			(clientRef != "" && t.TargetType == domain.TimeoutTargetClientApp && t.TargetID == clientRef)
		if hit && f.inForce(t, at) {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeTimeoutRepo) Update(_ context.Context, id string, p repository.UpdateTimeoutParams) (*domain.Timeout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byID[id]
	if !ok || !t.LiftedAt.IsZero() {
		return nil, repository.ErrNotFound
	}
	if p.Reason != nil {
		t.Reason = *p.Reason
	}
	if p.EndsAt != nil {
		t.EndsAt = *p.EndsAt
	}
	cp := *t
	return &cp, nil
}

func (f *fakeTimeoutRepo) Lift(_ context.Context, id, by string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byID[id]
	if !ok || !t.LiftedAt.IsZero() || (!t.EndsAt.IsZero() && !t.EndsAt.After(at)) {
		return false, nil
	}
	t.EndsAt, t.LiftedAt, t.LiftedBy = at, at, by
	return true, nil
}

func (f *fakeTimeoutRepo) ListToEnforce(_ context.Context, at time.Time, limit int) ([]*domain.Timeout, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Timeout
	for _, t := range f.byID {
		if t.EnforcedAt.IsZero() && f.inForce(t, at) {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartsAt.Before(out[j].StartsAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeTimeoutRepo) MarkEnforced(_ context.Context, id string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byID[id]
	if !ok || !t.EnforcedAt.IsZero() {
		return false, nil
	}
	t.EnforcedAt = at
	return true, nil
}

func (f *fakeTimeoutRepo) ClearEnforced(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.byID[id]; ok {
		t.EnforcedAt = time.Time{}
	}
	return nil
}

func (f *fakeTimeoutRepo) get(id string) *domain.Timeout {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.byID[id]
	return &cp
}

type fakeGroupRepo struct {
	repository.GroupRepository
	byID    map[string]*domain.Group
	members map[string][]string
}

func (f *fakeGroupRepo) GetByID(_ context.Context, id string) (*domain.Group, error) {
	if g, ok := f.byID[id]; ok {
		return g, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeGroupRepo) ListMemberIDs(_ context.Context, groupID string) ([]string, error) {
	return f.members[groupID], nil
}

// RevokeByClient completes fakeTokenRepo (identity_core_test.go). failNext
// makes the next call fail, once.
func (f *fakeTokenRepo) RevokeByClient(_ context.Context, clientRef string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRevokeByClient {
		f.failRevokeByClient = false
		return 0, errors.New("revoke failed")
	}
	n := 0
	for _, t := range f.byJTI {
		if t.ClientRefID == clientRef && !t.Revoked {
			t.Revoked = true
			n++
		}
	}
	return n, nil
}


const (
	toRealm    = "realm-demo"
	toMaster   = "realm-master"
	toAlice    = "u-alice"
	toBob      = "u-bob"
	toAdmin    = "u-admin"   // an administrator of master
	toOther    = "u-other"   // another administrator of master
	toStaff    = "g-staff"   // demo: alice and bob
	toAdmins   = "g-admins"  // master: "admins"
	toOps      = "g-ops"     // master: toAdmin is a member
	toSupport  = "g-support" // master: toOther only
	toApp      = "c-app"
	toConsole  = "c-console" // master: sso-admin
	toAppOther = "c-other-realm"
)

type timeoutFixture struct {
	now      time.Time
	repo     *fakeTimeoutRepo
	sessions *fakeSessionRepo
	tokens   *fakeTokenRepo
	audit    *fakeAuditRepo
	svc      *service.TimeoutService
	demo     *domain.Realm
	master   *domain.Realm
}

func newTimeoutFixture(t *testing.T) *timeoutFixture {
	t.Helper()
	f := &timeoutFixture{now: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }
	f.demo = &domain.Realm{ID: toRealm, Name: "demo"}
	f.master = &domain.Realm{ID: toMaster, Name: "master", IsSystemRealm: true}

	users := &fakeUserRepo{byID: map[string]*domain.User{
		toAlice: {ID: toAlice, RealmID: toRealm, Username: "alice", Status: domain.UserActive},
		toBob:   {ID: toBob, RealmID: toRealm, Username: "bob", Status: domain.UserActive},
		toAdmin: {ID: toAdmin, RealmID: toMaster, Username: "root", Status: domain.UserActive},
		toOther: {ID: toOther, RealmID: toMaster, Username: "ops2", Status: domain.UserActive},
	}}
	groups := &fakeGroupRepo{
		byID: map[string]*domain.Group{
			toStaff:   {ID: toStaff, RealmID: toRealm, Name: "staff"},
			toAdmins:  {ID: toAdmins, RealmID: toMaster, Name: service.AdminGroupName},
			toOps:     {ID: toOps, RealmID: toMaster, Name: "ops"},
			toSupport: {ID: toSupport, RealmID: toMaster, Name: "support"},
		},
		members: map[string][]string{toStaff: {toAlice, toBob}, toAdmins: {toAdmin}, toOps: {toAdmin}, toSupport: {toOther}},
	}
	clients := &fakeClientAppRepo{byID: map[string]*domain.ClientApp{
		toApp:      {ID: toApp, RealmID: toRealm, Name: "Wiki", ClientID: "wiki", Status: domain.ClientAppActive},
		toConsole:  {ID: toConsole, RealmID: toMaster, Name: "Admin console", ClientID: domain.InternalAdminClientID, Status: domain.ClientAppActive},
		toAppOther: {ID: toAppOther, RealmID: "realm-elsewhere", Name: "Other", ClientID: "other", Status: domain.ClientAppActive},
	}}
	f.repo = newFakeTimeoutRepo()
	f.repo.groups = map[string][]string{toAlice: {toStaff}, toBob: {toStaff}, toAdmin: {toAdmins, toOps}, toOther: {toSupport}}
	f.sessions = &fakeSessionRepo{now: clock, byID: map[string]*domain.Session{}}
	f.tokens = &fakeTokenRepo{byJTI: map[string]*domain.Token{}}
	f.audit = &fakeAuditRepo{}
	sessionSvc := service.NewSessionService(f.sessions, fakeSettingsRepo{}, f.tokens, fakeSessionCache{}, service.WithClock(clock))
	f.svc = service.NewTimeoutService(service.TimeoutDeps{
		Timeouts: f.repo, Users: users, Groups: groups, Clients: clients, Tokens: f.tokens,
		Sessions: sessionSvc, Audit: f.audit, Now: clock,
	})
	return f
}

// session gives userID an active session, with one access token for
// clientRef.
func (f *timeoutFixture) session(t *testing.T, userID, clientRef string) string {
	t.Helper()
	s, err := f.sessions.Create(context.Background(), repository.CreateSessionParams{
		RealmID: toRealm, UserID: userID, ExpiresAt: f.now.Add(8 * time.Hour)})
	require.NoError(t, err)
	jti := "jti-" + s.ID
	f.tokens.byJTI[jti] = &domain.Token{ID: "tok-" + s.ID, JTI: jti, SessionID: s.ID, ClientRefID: clientRef,
		Type: domain.TokenAccessToken}
	return s.ID
}

func (f *timeoutFixture) status(sessionID string) domain.SessionStatus {
	f.sessions.mu.Lock()
	defer f.sessions.mu.Unlock()
	return f.sessions.byID[sessionID].Status
}

func (f *timeoutFixture) tokenRevoked(sessionID string) bool {
	f.tokens.mu.Lock()
	defer f.tokens.mu.Unlock()
	return f.tokens.byJTI["jti-"+sessionID].Revoked
}

var cli = service.TimeoutActor{By: "cli:test"}

func (f *timeoutFixture) create(t *testing.T, in service.CreateTimeoutInput) *service.TimeoutChange {
	t.Helper()
	if in.Realm == nil {
		in.Realm = f.demo
	}
	if in.Reason == "" {
		in.Reason = "investigation"
	}
	if in.Actor.By == "" {
		in.Actor = cli
	}
	c, err := f.svc.Create(context.Background(), in)
	require.NoError(t, err)
	return c
}

func refusal(t *testing.T, err error, code, field string) {
	t.Helper()
	var r *service.TimeoutRefusal
	require.ErrorAs(t, err, &r)
	require.Equal(t, code, r.Code, r.Message)
	if field != "" {
		require.Equal(t, field, r.Field)
	}
}


func TestTimeoutCheck(t *testing.T) {
	ctx := context.Background()

	t.Run("a timeout on the user blocks them from its start to its end", func(t *testing.T) {
		f := newTimeoutFixture(t)
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice,
			StartsAt: f.now.Add(time.Hour), EndsAt: f.now.Add(3 * time.Hour)})

		got, err := f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.Nil(t, got, "scheduled: not in force yet")

		f.now = f.now.Add(time.Hour)
		got, err = f.svc.ActiveTimeout(ctx, toAlice, toApp)
		require.NoError(t, err)
		require.NotNil(t, got, "started")
		require.Equal(t, toAlice, got.TargetID)

		got, err = f.svc.ActiveTimeout(ctx, toBob, toApp)
		require.NoError(t, err)
		require.Nil(t, got, "bob is not targeted")

		f.now = f.now.Add(2 * time.Hour)
		got, err = f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.Nil(t, got, "past its end")
	})

	t.Run("a timeout on a group blocks every member", func(t *testing.T) {
		f := newTimeoutFixture(t)
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetGroup, TargetID: toStaff})
		for _, u := range []string{toAlice, toBob} {
			got, err := f.svc.ActiveTimeout(ctx, u, "")
			require.NoError(t, err)
			require.NotNil(t, got, u)
			require.True(t, got.OnPeople())
		}
	})

	t.Run("a timeout on a client blocks everybody on that client only", func(t *testing.T) {
		f := newTimeoutFixture(t)
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetClientApp, TargetID: toApp})
		got, err := f.svc.ActiveTimeout(ctx, toAlice, toApp)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.False(t, got.OnPeople())

		got, err = f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.Nil(t, got, "signing in to the IdP itself is fine")
	})

	t.Run("the user's own timeout comes before the client's", func(t *testing.T) {
		f := newTimeoutFixture(t)
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetClientApp, TargetID: toApp})
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		got, err := f.svc.ActiveTimeout(ctx, toAlice, toApp)
		require.NoError(t, err)
		require.True(t, got.OnPeople())
	})

	t.Run("a lifted timeout no longer blocks", func(t *testing.T) {
		f := newTimeoutFixture(t)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		_, err := f.svc.Lift(ctx, f.demo, c.Timeout.ID, cli)
		require.NoError(t, err)
		got, err := f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("a database error is returned, never taken for no timeout", func(t *testing.T) {
		f := newTimeoutFixture(t)
		f.repo.failInForce = true
		_, err := f.svc.ActiveTimeout(ctx, toAlice, "")
		require.Error(t, err)
	})
}

// The checker in the sign-in: the password is right, the timeout says no,
// with an error that tells the user from the application.
func TestTimeoutBlocksSignIn(t *testing.T) {
	ctx := context.Background()
	f := newTimeoutFixture(t)
	hash, err := service.HashPassword("correct horse battery staple")
	require.NoError(t, err)
	users := &fakeUserRepo{byID: map[string]*domain.User{
		toAlice: {ID: toAlice, RealmID: toRealm, Username: "alice", Status: domain.UserActive, PasswordHash: hash},
	}}
	attempts := &fakeLoginAttemptRepo{}
	auth := service.NewAuthService(users, attempts, service.WithTimeoutChecker(f.svc))
	signIn := func(clientRef string) error {
		_, err := auth.AuthenticateLocal(ctx, service.AuthenticateLocalParams{RealmID: toRealm, Identifier: "alice",
			Password: "correct horse battery staple", ClientRef: clientRef})
		return err
	}

	require.NoError(t, signIn(toApp))

	app := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetClientApp, TargetID: toApp})
	err = signIn(toApp)
	require.ErrorIs(t, err, core.ErrTimeoutActive)
	require.True(t, core.TimeoutOnClient(err), "the application is suspended")
	require.Equal(t, domain.LoginFailureTimeoutActive, attempts.last().FailureReason)
	require.NoError(t, signIn(""), "the IdP itself is not suspended")

	f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetGroup, TargetID: toStaff})
	err = signIn(toApp)
	require.ErrorIs(t, err, service.ErrTimeoutActive)
	require.False(t, core.TimeoutOnClient(err), "the user's group comes first")

	_, err = f.svc.Lift(ctx, f.demo, app.Timeout.ID, cli)
	require.NoError(t, err)
	require.False(t, core.TimeoutOnClient(signIn(toApp)))

	_, err = auth.AuthenticateLocal(ctx, service.AuthenticateLocalParams{RealmID: toRealm, Identifier: "alice", Password: "wrong"})
	require.ErrorIs(t, err, service.ErrInvalidCredentials, "a wrong password never reveals the timeout")
}


func TestTimeoutCreateValidation(t *testing.T) {
	ctx := context.Background()
	f := newTimeoutFixture(t)
	base := func() service.CreateTimeoutInput {
		return service.CreateTimeoutInput{Realm: f.demo, TargetType: domain.TimeoutTargetUser, TargetID: toAlice,
			Reason: "investigation", Actor: cli}
	}
	cases := []struct {
		name  string
		edit  func(*service.CreateTimeoutInput)
		field string
	}{
		{"no reason", func(in *service.CreateTimeoutInput) { in.Reason = "   " }, "reason"},
		{"reason too long", func(in *service.CreateTimeoutInput) { in.Reason = strings.Repeat("é", 501) }, "reason"},
		{"unknown target type", func(in *service.CreateTimeoutInput) { in.TargetType = "realm" }, "target_type"},
		{"no target", func(in *service.CreateTimeoutInput) { in.TargetID = "" }, "target_id"},
		{"unknown user", func(in *service.CreateTimeoutInput) { in.TargetID = "nobody" }, "target_id"},
		{"a group of another realm", func(in *service.CreateTimeoutInput) {
			in.TargetType, in.TargetID = domain.TimeoutTargetGroup, toOps
		}, "target_id"},
		{"a client of another realm", func(in *service.CreateTimeoutInput) {
			in.TargetType, in.TargetID = domain.TimeoutTargetClientApp, toAppOther
		}, "target_id"},
		{"start long ago", func(in *service.CreateTimeoutInput) { in.StartsAt = f.now.Add(-time.Hour) }, "starts_at"},
		{"start too far ahead", func(in *service.CreateTimeoutInput) { in.StartsAt = f.now.AddDate(1, 1, 0) }, "starts_at"},
		{"end before the start", func(in *service.CreateTimeoutInput) {
			in.StartsAt, in.EndsAt = f.now.Add(2*time.Hour), f.now.Add(time.Hour)
		}, "ends_at"},
		{"end in less than a minute", func(in *service.CreateTimeoutInput) { in.EndsAt = f.now.Add(30 * time.Second) }, "ends_at"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base()
			c.edit(&in)
			_, err := f.svc.Create(ctx, in)
			refusal(t, err, "invalid_request", c.field)
		})
	}

	t.Run("a start a minute ago means now, the reason is trimmed", func(t *testing.T) {
		in := base()
		in.StartsAt, in.Reason = f.now.Add(-time.Minute), "  spam  "
		c, err := f.svc.Create(ctx, in)
		require.NoError(t, err)
		require.Equal(t, f.now, c.Timeout.StartsAt)
		require.Equal(t, "spam", c.Timeout.Reason)
		require.Equal(t, "alice", c.Target.Name)
		require.Equal(t, "cli:test", c.Timeout.CreatedBy)
	})
}

func TestTimeoutGuardrails(t *testing.T) {
	ctx := context.Background()
	admin := service.TimeoutActor{By: "user:" + toAdmin, UserID: toAdmin}
	cases := []struct {
		name  string
		actor service.TimeoutActor
		typ   domain.TimeoutTargetType
		id    string
		code  string // "" = allowed
	}{
		{"yourself", admin, domain.TimeoutTargetUser, toAdmin, "timeout_self"},
		{"another administrator", admin, domain.TimeoutTargetUser, toOther, ""},
		{"the admins group", admin, domain.TimeoutTargetGroup, toAdmins, "timeout_admin_console"},
		{"the admins group, from the CLI", cli, domain.TimeoutTargetGroup, toAdmins, "timeout_admin_console"},
		{"a group of yours", admin, domain.TimeoutTargetGroup, toOps, "timeout_self"},
		{"a group of others", admin, domain.TimeoutTargetGroup, toSupport, ""},
		{"the admin console's client", admin, domain.TimeoutTargetClientApp, toConsole, "timeout_admin_console"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newTimeoutFixture(t)
			_, err := f.svc.Create(ctx, service.CreateTimeoutInput{Realm: f.master, TargetType: c.typ, TargetID: c.id,
				Reason: "test", Actor: c.actor})
			if c.code == "" {
				require.NoError(t, err)
				return
			}
			refusal(t, err, c.code, "target_id")
		})
	}
}


func TestTimeoutSignOut(t *testing.T) {
	ctx := context.Background()

	t.Run("starting at once signs the user out, sessions and tokens", func(t *testing.T) {
		f := newTimeoutFixture(t)
		s1, s2, other := f.session(t, toAlice, toApp), f.session(t, toAlice, toApp), f.session(t, toBob, toApp)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		require.Equal(t, &service.TimeoutSignOut{Users: 1, Sessions: 2}, c.SignOut)
		require.False(t, c.SignOutPending)
		for _, s := range []string{s1, s2} {
			require.Equal(t, domain.SessionRevoked, f.status(s))
			require.True(t, f.tokenRevoked(s))
		}
		require.Equal(t, domain.SessionActive, f.status(other))
		require.Equal(t, f.now, f.repo.get(c.Timeout.ID).EnforcedAt)

		last := f.audit.entries[len(f.audit.entries)-1]
		require.Equal(t, "timeout_enforced", last.Action)
		require.Equal(t, 2, last.Details["sessions_revoked"])
		require.Equal(t, "cli:test", last.Details["triggered_by"])
	})

	t.Run("a group: every member", func(t *testing.T) {
		f := newTimeoutFixture(t)
		a, b := f.session(t, toAlice, toApp), f.session(t, toBob, toApp)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetGroup, TargetID: toStaff})
		require.Equal(t, &service.TimeoutSignOut{Users: 2, Sessions: 2}, c.SignOut)
		require.Equal(t, domain.SessionRevoked, f.status(a))
		require.Equal(t, domain.SessionRevoked, f.status(b))
	})

	t.Run("a client: its tokens, not the users' sessions", func(t *testing.T) {
		f := newTimeoutFixture(t)
		onApp, elsewhere := f.session(t, toAlice, toApp), f.session(t, toBob, "c-another-app")
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetClientApp, TargetID: toApp})
		require.Equal(t, &service.TimeoutSignOut{Tokens: 1}, c.SignOut)
		require.True(t, f.tokenRevoked(onApp))
		require.Equal(t, domain.SessionActive, f.status(onApp), "the SSO session still serves the other applications")
		require.False(t, f.tokenRevoked(elsewhere))
	})

	t.Run("a scheduled timeout: the enforcer signs out at its start, once", func(t *testing.T) {
		f := newTimeoutFixture(t)
		s := f.session(t, toAlice, toApp)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice,
			StartsAt: f.now.Add(2 * time.Hour)})
		require.Nil(t, c.SignOut)

		n, err := f.svc.EnforceDue(ctx)
		require.NoError(t, err)
		require.Zero(t, n, "not started")
		require.Equal(t, domain.SessionActive, f.status(s))

		f.now = f.now.Add(2*time.Hour + 10*time.Second)
		n, err = f.svc.EnforceDue(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.Equal(t, domain.SessionRevoked, f.status(s))
		require.Equal(t, service.TimeoutEnforcerActor, f.audit.entries[len(f.audit.entries)-1].Details["triggered_by"])

		n, err = f.svc.EnforceDue(ctx)
		require.NoError(t, err)
		require.Zero(t, n, "already done")
	})

	t.Run("a lifted scheduled timeout is never enforced", func(t *testing.T) {
		f := newTimeoutFixture(t)
		s := f.session(t, toAlice, toApp)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice,
			StartsAt: f.now.Add(time.Hour)})
		lifted, err := f.svc.Lift(ctx, f.demo, c.Timeout.ID, cli)
		require.NoError(t, err)
		require.Equal(t, domain.TimeoutLifted, lifted.Timeout.StatusAt(f.now))

		f.now = f.now.Add(2 * time.Hour)
		n, err := f.svc.EnforceDue(ctx)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, domain.SessionActive, f.status(s))
		got, err := f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("a failed sign-out is retried by the enforcer", func(t *testing.T) {
		f := newTimeoutFixture(t)
		s := f.session(t, toAlice, toApp)
		f.tokens.failRevokeByClient = true
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetClientApp, TargetID: toApp})
		require.True(t, c.SignOutPending)
		require.Zero(t, f.repo.get(c.Timeout.ID).EnforcedAt, "the claim was undone")

		got, err := f.svc.ActiveTimeout(ctx, toAlice, toApp)
		require.NoError(t, err)
		require.NotNil(t, got, "the check blocks meanwhile")

		n, err := f.svc.EnforceDue(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		require.True(t, f.tokenRevoked(s))
	})

	t.Run("RunEnforcer stops with its context", func(t *testing.T) {
		f := newTimeoutFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { f.svc.RunEnforcer(ctx, time.Millisecond); close(done) }()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("RunEnforcer did not stop")
		}
	})
}


func TestTimeoutUpdateAndLift(t *testing.T) {
	ctx := context.Background()

	t.Run("the reason and the end change; the end can be removed", func(t *testing.T) {
		f := newTimeoutFixture(t)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice,
			EndsAt: f.now.Add(time.Hour)})
		reason, end := "fraud check", f.now.Add(48*time.Hour)
		u, err := f.svc.Update(ctx, service.UpdateTimeoutInput{Realm: f.demo, ID: c.Timeout.ID, Reason: &reason, EndsAt: &end, Actor: cli})
		require.NoError(t, err)
		require.Equal(t, []string{"reason", "ends_at"}, u.Changed)
		require.Equal(t, end, u.Timeout.EndsAt)

		none := time.Time{}
		u, err = f.svc.Update(ctx, service.UpdateTimeoutInput{Realm: f.demo, ID: c.Timeout.ID, EndsAt: &none, Actor: cli})
		require.NoError(t, err)
		require.True(t, u.Timeout.EndsAt.IsZero(), "no end any more")

		u, err = f.svc.Update(ctx, service.UpdateTimeoutInput{Realm: f.demo, ID: c.Timeout.ID, Reason: &reason, Actor: cli})
		require.NoError(t, err)
		require.Empty(t, u.Changed, "nothing changed")
	})

	t.Run("the end must stay ahead of now", func(t *testing.T) {
		f := newTimeoutFixture(t)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		f.now = f.now.Add(time.Hour)
		soon := f.now.Add(10 * time.Second)
		_, err := f.svc.Update(ctx, service.UpdateTimeoutInput{Realm: f.demo, ID: c.Timeout.ID, EndsAt: &soon, Actor: cli})
		refusal(t, err, "invalid_request", "ends_at")
	})

	t.Run("lift ends it now; an ended or lifted timeout cannot change", func(t *testing.T) {
		f := newTimeoutFixture(t)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		f.now = f.now.Add(time.Minute)
		l, err := f.svc.Lift(ctx, f.demo, c.Timeout.ID, service.TimeoutActor{By: "user:" + toAdmin, UserID: toAdmin})
		require.NoError(t, err)
		require.Equal(t, f.now, l.Timeout.LiftedAt)
		require.Equal(t, f.now, l.Timeout.EndsAt)
		require.Equal(t, "user:"+toAdmin, l.Timeout.LiftedBy)
		require.Equal(t, domain.TimeoutLifted, l.Timeout.StatusAt(f.now))

		_, err = f.svc.Lift(ctx, f.demo, c.Timeout.ID, cli)
		refusal(t, err, "timeout_over", "")
		reason := "again"
		_, err = f.svc.Update(ctx, service.UpdateTimeoutInput{Realm: f.demo, ID: c.Timeout.ID, Reason: &reason, Actor: cli})
		refusal(t, err, "timeout_over", "")

		ended := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toBob,
			EndsAt: f.now.Add(time.Hour)})
		f.now = f.now.Add(2 * time.Hour)
		_, err = f.svc.Lift(ctx, f.demo, ended.Timeout.ID, cli)
		refusal(t, err, "timeout_over", "")
	})

	t.Run("another realm's timeout is not found", func(t *testing.T) {
		f := newTimeoutFixture(t)
		c := f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		_, err := f.svc.Lift(ctx, f.master, c.Timeout.ID, cli)
		refusal(t, err, "not_found", "")
	})

	t.Run("lift every timeout of a realm (recovery)", func(t *testing.T) {
		f := newTimeoutFixture(t)
		admin := service.TimeoutActor{By: "user:" + toOther, UserID: toOther}
		f.create(t, service.CreateTimeoutInput{Realm: f.master, TargetType: domain.TimeoutTargetUser, TargetID: toAdmin, Actor: admin})
		f.create(t, service.CreateTimeoutInput{Realm: f.master, TargetType: domain.TimeoutTargetUser, TargetID: toOther,
			StartsAt: f.now.Add(time.Hour)})
		f.create(t, service.CreateTimeoutInput{TargetType: domain.TimeoutTargetUser, TargetID: toAlice})
		lifted, err := f.svc.LiftAllInRealm(ctx, f.master, cli)
		require.NoError(t, err)
		require.Len(t, lifted, 2)
		got, err := f.svc.ActiveTimeout(ctx, toAlice, "")
		require.NoError(t, err)
		require.NotNil(t, got, "other realms are left alone")
	})
}

func TestTimeoutStatus(t *testing.T) {
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		t    domain.Timeout
		want domain.TimeoutStatus
	}{
		{"scheduled", domain.Timeout{StartsAt: now.Add(time.Minute)}, domain.TimeoutScheduled},
		{"active, no end", domain.Timeout{StartsAt: now}, domain.TimeoutActive},
		{"active, with an end", domain.Timeout{StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Second)}, domain.TimeoutActive},
		{"ended", domain.Timeout{StartsAt: now.Add(-time.Hour), EndsAt: now}, domain.TimeoutEnded},
		{"lifted", domain.Timeout{StartsAt: now.Add(-time.Hour), EndsAt: now, LiftedAt: now}, domain.TimeoutLifted},
		{"cancelled before its start", domain.Timeout{StartsAt: now.Add(time.Hour), EndsAt: now, LiftedAt: now}, domain.TimeoutLifted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, c.t.StatusAt(now))
			require.Equal(t, c.want == domain.TimeoutActive, c.t.InForceAt(now) && c.t.LiftedAt.IsZero())
		})
	}
}
