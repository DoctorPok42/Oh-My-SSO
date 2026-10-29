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



type fakeConsentRepo struct {
	repository.ConsentRepository
	mu   sync.Mutex
	now  func() time.Time
	seq  int
	rows map[string]*domain.Consent // id -> row
	// conflictOnce makes the next Create fail with ErrConflict after
	// inserting the given row, like another tab winning the race.
	conflictOnce *domain.Consent
	reads        int // GetByUserAndClient calls
}

func newFakeConsentRepo(now func() time.Time) *fakeConsentRepo {
	return &fakeConsentRepo{now: now, rows: map[string]*domain.Consent{}}
}

func (f *fakeConsentRepo) find(userID, clientRef string) *domain.Consent {
	for _, c := range f.rows {
		if c.UserID == userID && c.ClientRefID == clientRef {
			return c
		}
	}
	return nil
}

func (f *fakeConsentRepo) Create(_ context.Context, p repository.CreateConsentParams) (*domain.Consent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conflictOnce != nil {
		other := f.conflictOnce
		f.conflictOnce = nil
		f.rows[other.ID] = other
		return nil, fmt.Errorf("%w: unique (user_id, client_ref_id)", repository.ErrConflict)
	}
	if f.find(p.UserID, p.ClientRefID) != nil {
		return nil, fmt.Errorf("%w: unique (user_id, client_ref_id)", repository.ErrConflict)
	}
	f.seq++
	now := f.now()
	c := &domain.Consent{ID: fmt.Sprintf("consent-%d", f.seq), UserID: p.UserID, ClientRefID: p.ClientRefID,
		Scopes: slices.Clone(p.Scopes), Status: domain.ConsentGranted, GrantedAt: now, CreatedAt: now, UpdatedAt: now}
	f.rows[c.ID] = c
	cp := *c
	return &cp, nil
}

func (f *fakeConsentRepo) GetByUserAndClient(_ context.Context, userID, clientRef string) (*domain.Consent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if c := f.find(userID, clientRef); c != nil {
		cp := *c
		cp.Scopes = slices.Clone(c.Scopes)
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeConsentRepo) ListByUser(_ context.Context, userID string) ([]*domain.Consent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Consent
	for _, c := range f.rows {
		if c.UserID == userID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *fakeConsentRepo) Update(_ context.Context, id string, p repository.UpdateConsentParams) (*domain.Consent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.rows[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if p.Scopes != nil {
		c.Scopes = slices.Clone(p.Scopes)
	}
	if p.Status != nil {
		c.Status = *p.Status
	}
	if p.GrantedAt != nil {
		c.GrantedAt = *p.GrantedAt
	}
	if p.ClearRevokedAt {
		c.RevokedAt = time.Time{}
	}
	c.UpdatedAt = f.now()
	cp := *c
	return &cp, nil
}

func (f *fakeConsentRepo) Revoke(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.rows[id]
	if !ok {
		return repository.ErrNotFound
	}
	c.Status, c.RevokedAt = domain.ConsentRevoked, f.now()
	return nil
}

func (f *fakeConsentRepo) row(userID, clientRef string) *domain.Consent {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.find(userID, clientRef)
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func (f *fakeConsentRepo) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

// RevokeByUserAndClient mimics the real query: access, refresh and ID
// tokens of the client, in any session of the user.
func (f *fakeTokenRepo) RevokeByUserAndClient(_ context.Context, userID, clientRef string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range f.byJTI {
		if t.Revoked || t.ClientRefID != clientRef || t.Type == domain.TokenSAMLSession {
			continue
		}
		if f.sessionUser == nil || f.sessionUser(t.SessionID) != userID {
			continue
		}
		t.Revoked = true
		n++
	}
	return n, nil
}

// Update: only what SetClientRequirement changes.
func (f *fakeClientAppRepo) Update(_ context.Context, id string, p repository.UpdateClientAppParams) (*domain.ClientApp, error) {
	c, ok := f.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if p.RequireConsent != nil {
		c.RequireConsent = *p.RequireConsent
	}
	return c, nil
}

func items(scopes ...string) []core.ConsentItem {
	out := make([]core.ConsentItem, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, core.ConsentItem{Scope: s, Title: "title of " + s})
	}
	return out
}

func (f *coreFixture) check(t *testing.T, sessionID, clientRef string, force bool, scopes ...string) *core.ConsentDecision {
	t.Helper()
	d, err := f.core.CheckConsent(context.Background(), core.ConsentCheck{
		SessionID: sessionID, ClientRef: clientRef, Scopes: scopes, Force: force,
	})
	require.NoError(t, err)
	return d
}

func (f *coreFixture) grant(t *testing.T, sessionID, clientRef string, scopes ...string) *domain.Consent {
	t.Helper()
	c, err := f.core.GrantConsent(context.Background(), core.ConsentGrant{
		SessionID: sessionID, ClientRef: clientRef, Items: items(scopes...), IPAddress: "203.0.113.7", UserAgent: "test",
	})
	require.NoError(t, err)
	return c
}

func (f *coreFixture) auditActions(action string) []repository.CreateAuditLogParams {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var out []repository.CreateAuditLogParams
	for _, e := range f.audit.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}


func TestConsentRequired(t *testing.T) {
	granted := &domain.Consent{Status: domain.ConsentGranted, Scopes: []string{"profile", "email"}}
	revoked := &domain.Consent{Status: domain.ConsentRevoked, Scopes: []string{"profile", "email"}}
	identityOnly := &domain.Consent{Status: domain.ConsentGranted, Scopes: []string{}}

	cases := []struct {
		name       string
		require    bool
		stored     *domain.Consent
		scopes     []string
		force      bool
		want       bool
		missing    []string
		previously bool
	}{
		{"require_consent off: never", false, nil, []string{"profile"}, false, false, []string{"profile"}, false},
		{"require_consent off, prompt=consent: asked", false, granted, []string{"profile"}, true, true, nil, true},
		{"first use", true, nil, []string{"profile", "email"}, false, true, []string{"profile", "email"}, false},
		{"first use, identity only", true, nil, nil, false, true, nil, false},
		{"same scopes again: not asked", true, granted, []string{"email", "profile"}, false, false, nil, true},
		{"fewer scopes: not asked", true, granted, []string{"email"}, false, false, nil, true},
		{"a new scope: asked, only it is missing", true, granted, []string{"profile", "groups", "email"}, false, true, []string{"groups"}, true},
		{"after a revocation: asked for everything", true, revoked, []string{"profile"}, false, true, []string{"profile"}, false},
		{"identity only, approved before: not asked", true, identityOnly, nil, false, false, nil, true},
		{"prompt=consent with everything approved: asked", true, granted, []string{"profile"}, true, true, nil, true},
		{"duplicates and empty names ignored", true, nil, []string{"email", "", "email"}, false, true, []string{"email"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := service.ConsentRequired(c.require, c.stored, c.scopes, c.force)
			require.Equal(t, c.want, d.Required)
			require.Equal(t, c.missing, d.Missing)
			require.Equal(t, c.previously, d.Previously)
		})
	}
}


func TestIdentityCore_Consent_DefinitionOfDone(t *testing.T) {
	ctx := context.Background()

	t.Run("asked once for the same scopes", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		d := f.check(t, sess.ID, clientConsent, false, "profile", "email")
		require.True(t, d.Required, "first use of a client with require_consent")
		require.False(t, d.Previously)

		f.grant(t, sess.ID, clientConsent, "profile", "email")
		require.False(t, f.check(t, sess.ID, clientConsent, false, "profile", "email").Required)

		// Another session of the same user (another browser, the next day):
		// the consent belongs to the user, not to the session.
		other := f.aliceSession(t).Session
		require.False(t, f.check(t, other.ID, clientConsent, false, "email", "profile").Required)
	})

	t.Run("asked again when a new scope appears, merged into one row", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		f.grant(t, sess.ID, clientConsent, "profile", "email")

		d := f.check(t, sess.ID, clientConsent, false, "profile", "email", "groups")
		require.True(t, d.Required)
		require.Equal(t, []string{"groups"}, d.Missing, "only the new scope is missing")
		require.True(t, d.Previously, "the screen can say: more than before")

		c := f.grant(t, sess.ID, clientConsent, "profile", "email", "groups")
		require.Equal(t, []string{"profile", "email", "groups"}, c.Scopes)
		require.Equal(t, 1, f.consents.count(), "one row per user and client (UNIQUE), scopes merged")
		require.False(t, f.check(t, sess.ID, clientConsent, false, "groups", "profile").Required)
	})

	t.Run("never asked when require_consent is false", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		d := f.check(t, sess.ID, clientOIDC, false, "profile", "email", "offline_access")
		require.False(t, d.Required)
		require.Zero(t, f.consents.reads, "no database read for clients without require_consent")
		require.Zero(t, f.consents.count())
	})

	t.Run("prompt=consent asks even when not required or already approved", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		require.True(t, f.check(t, sess.ID, clientOIDC, true, "profile").Required)

		f.grant(t, sess.ID, clientConsent, "profile")
		require.True(t, f.check(t, sess.ID, clientConsent, true, "profile").Required)
	})

	t.Run("a user cannot answer for another realm's client, nor without a session", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		f.clients.byID["client-elsewhere"] = &domain.ClientApp{ID: "client-elsewhere", RealmID: "realm-b",
			Protocol: domain.ClientAppProtocolOIDC, Status: domain.ClientAppActive, RequireConsent: true}

		_, err := f.core.CheckConsent(ctx, core.ConsentCheck{SessionID: sess.ID, ClientRef: "client-elsewhere"})
		require.ErrorIs(t, err, core.ErrClientNotFound)
		_, err = f.core.GrantConsent(ctx, core.ConsentGrant{SessionID: sess.ID, ClientRef: "client-elsewhere", Items: items("email")})
		require.ErrorIs(t, err, core.ErrClientNotFound)

		require.NoError(t, f.core.RevokeSession(ctx, sess.ID, domain.SessionRevokedUserLogout))
		_, err = f.core.GrantConsent(ctx, core.ConsentGrant{SessionID: sess.ID, ClientRef: clientConsent, Items: items("email")})
		require.ErrorIs(t, err, core.ErrSessionInvalid)
		require.Zero(t, f.consents.count())
	})
}

func TestIdentityCore_GrantConsent_AuditAndEmail(t *testing.T) {
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session

	f.grant(t, sess.ID, clientConsent, "profile")
	granted := f.auditActions("consent_granted")
	require.Len(t, granted, 1)
	require.Equal(t, aliceID, granted[0].UserID)
	require.Equal(t, "Partner App", granted[0].Details["client"])
	require.Equal(t, []string{"profile"}, granted[0].Details["added"])
	ev := f.notifier.last()
	require.Equal(t, domain.NotificationAppConnected, ev.Kind)
	require.Equal(t, "Partner App", ev.ClientName)
	require.Equal(t, []string{"title of profile"}, ev.Access)
	require.False(t, ev.AccessAdded)

	// The same approval again: nothing new, nothing written, no e-mail.
	f.grant(t, sess.ID, clientConsent, "profile")
	require.Len(t, f.auditActions("consent_granted"), 1)
	require.Len(t, f.notifier.kinds(), 1)

	// More scopes: the e-mail lists only the new ones.
	f.grant(t, sess.ID, clientConsent, "profile", "email")
	ev = f.notifier.last()
	require.Equal(t, []string{"title of email"}, ev.Access)
	require.True(t, ev.AccessAdded)
}

func TestIdentityCore_GrantConsent_ConcurrentTabs(t *testing.T) {
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session
	// The other tab created the row between our read and our insert.
	f.consents.conflictOnce = &domain.Consent{ID: "consent-other-tab", UserID: aliceID, ClientRefID: clientConsent,
		Scopes: []string{"profile"}, Status: domain.ConsentGranted, GrantedAt: f.now}

	c := f.grant(t, sess.ID, clientConsent, "email")
	require.Equal(t, "consent-other-tab", c.ID)
	require.Equal(t, []string{"profile", "email"}, c.Scopes)
	require.Equal(t, 1, f.consents.count())
}

func TestIdentityCore_DenyConsent(t *testing.T) {
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session

	require.NoError(t, f.core.DenyConsent(context.Background(), core.ConsentDenial{
		SessionID: sess.ID, ClientRef: clientConsent, Scopes: []string{"email"},
	}))
	denied := f.auditActions("consent_denied")
	require.Len(t, denied, 1)
	require.Equal(t, domain.AuditLogFailure, denied[0].Status)
	require.Zero(t, f.consents.count(), "a refusal is not remembered: the next request asks again")
	require.True(t, f.check(t, sess.ID, clientConsent, false, "email").Required)
}

func TestConsentService_Revoke(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session
	bob := f.sessionFor(t, bobID).Session
	f.grant(t, sess.ID, clientConsent, "profile", "email")

	mk := func(jti, sessionID, clientRef string, typ domain.TokenType) {
		_, err := f.tokens.Create(ctx, repository.CreateTokenParams{SessionID: sessionID, ClientRefID: clientRef,
			Type: typ, JTI: jti, ExpiresAt: f.now.Add(time.Hour)})
		require.NoError(t, err)
	}
	mk("at-1", sess.ID, clientConsent, domain.TokenAccessToken)
	mk("rt-1", sess.ID, clientConsent, domain.TokenRefreshToken)
	mk("at-other-client", sess.ID, clientOIDC, domain.TokenAccessToken)
	mk("at-bob", bob.ID, clientConsent, domain.TokenAccessToken)
	mk("saml-participant", sess.ID, clientConsent, domain.TokenSAMLSession)

	res, err := f.consent.Revoke(ctx, service.RevokeConsentInput{RealmID: realmA, UserID: aliceID, ClientRef: clientConsent,
		Actor: service.PolicyActor{TriggeredBy: "cli:admin"}, Reason: "test"})
	require.NoError(t, err)
	require.Equal(t, 2, res.TokensRevoked)
	require.True(t, f.tokens.get("at-1").Revoked)
	require.True(t, f.tokens.get("rt-1").Revoked, "a refresh token cannot keep the access alive")
	require.False(t, f.tokens.get("at-other-client").Revoked, "other clients keep their tokens")
	require.False(t, f.tokens.get("at-bob").Revoked, "other users keep theirs")
	require.False(t, f.tokens.get("saml-participant").Revoked, "Single Logout still needs the participant record")
	require.Equal(t, domain.ConsentRevoked, f.consents.row(aliceID, clientConsent).Status)
	require.Len(t, f.auditActions("consent_revoked"), 1)

	// Asked again, as for a first use.
	d := f.check(t, sess.ID, clientConsent, false, "profile")
	require.True(t, d.Required)
	require.False(t, d.Previously)

	// Approving again starts from the new answer: what was approved before
	// the revocation does not come back on its own.
	f.advance(time.Minute) // within the session's idle timeout
	c := f.grant(t, sess.ID, clientConsent, "email")
	require.Equal(t, domain.ConsentGranted, c.Status)
	require.Equal(t, []string{"email"}, c.Scopes)
	require.True(t, c.RevokedAt.IsZero())
	require.Equal(t, f.now, c.GrantedAt)
	require.Equal(t, 1, f.consents.count())

	// Revoking twice, or a consent that never existed.
	_, err = f.consent.Revoke(ctx, service.RevokeConsentInput{RealmID: realmA, UserID: bobID, ClientRef: clientConsent})
	require.ErrorIs(t, err, service.ErrConsentNotFound)
	_, err = f.consent.Revoke(ctx, service.RevokeConsentInput{RealmID: "realm-b", UserID: aliceID, ClientRef: clientConsent})
	require.ErrorIs(t, err, service.ErrConsentNotFound, "never across realms")
}

func TestConsentService_ListAndClientSetting(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session
	f.grant(t, sess.ID, clientConsent, "email")

	list, err := f.consent.List(ctx, realmA, aliceID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "Partner App", list[0].Client.Name)

	app, err := f.consent.SetClientRequirement(ctx, service.SetClientConsentInput{RealmID: realmA, ClientRef: clientConsent,
		Required: false, Actor: service.PolicyActor{TriggeredBy: "cli:admin"}})
	require.NoError(t, err)
	require.False(t, app.RequireConsent)
	require.Len(t, f.auditActions("consent_policy_changed"), 1)
	require.False(t, f.check(t, sess.ID, clientConsent, false, "email", "groups").Required, "off: never asked")

	f.clients.byID[clientConsent].ManagedBy = domain.ClientAppManagedByConfig
	_, err = f.consent.SetClientRequirement(ctx, service.SetClientConsentInput{RealmID: realmA, ClientRef: clientConsent, Required: true})
	require.ErrorIs(t, err, service.ErrManagedByConfig, "a client of the configuration file changes in the file")
}

func TestIdentityCore_Consent_FailClosedWithoutService(t *testing.T) {
	f := newCoreFixture(t)
	sess := f.aliceSession(t).Session
	bare := service.NewIdentityCore(service.IdentityCoreDeps{Clients: f.clients})

	_, err := bare.CheckConsent(context.Background(), core.ConsentCheck{SessionID: sess.ID, ClientRef: clientConsent})
	require.ErrorIs(t, err, core.ErrConsentNotConfigured)
	d, err := bare.CheckConsent(context.Background(), core.ConsentCheck{SessionID: sess.ID, ClientRef: clientOIDC})
	require.NoError(t, err)
	require.False(t, d.Required)
	_, err = bare.GrantConsent(context.Background(), core.ConsentGrant{SessionID: sess.ID, ClientRef: clientConsent})
	require.ErrorIs(t, err, core.ErrConsentNotConfigured)
}
