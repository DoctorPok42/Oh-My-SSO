package service_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/keymanager"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/sessioncache"
)

// These tests exercise the whole IdentityCore in memory: no HTTP server, no
// Postgres, no Valkey, no Vault. That is the Step 7 Definition of Done.
//
// Fakes embed the repository interface they implement. The embedded value is
// nil, so calling a method the fake does not override panics: a test that
// hits an unexpected code path fails loudly instead of silently passing.

// --- in-memory fakes -------------------------------------------------------

type fakeUserRepo struct {
	repository.UserRepository
	byID map[string]*domain.User
}

func (f *fakeUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeUserRepo) GetByRealmAndUsername(_ context.Context, realmID, username string) (*domain.User, error) {
	for _, u := range f.byID {
		if u.RealmID == realmID && u.Username == username {
			return u, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeUserRepo) GetByRealmAndEmail(_ context.Context, realmID, email string) (*domain.User, error) {
	for _, u := range f.byID {
		if u.RealmID == realmID && u.Email == email {
			return u, nil
		}
	}
	return nil, repository.ErrNotFound
}

type fakeLoginAttemptRepo struct {
	repository.LoginAttemptRepository
	attempts []repository.CreateLoginAttemptParams
}

func (f *fakeLoginAttemptRepo) Create(_ context.Context, p repository.CreateLoginAttemptParams) (*domain.LoginAttempt, error) {
	f.attempts = append(f.attempts, p)
	return &domain.LoginAttempt{Status: p.Status, FailureReason: p.FailureReason}, nil
}

func (f *fakeLoginAttemptRepo) last() repository.CreateLoginAttemptParams {
	return f.attempts[len(f.attempts)-1]
}

type fakeSessionRepo struct {
	repository.SessionRepository
	mu   sync.Mutex
	now  func() time.Time
	seq  int
	byID map[string]*domain.Session
}

func (f *fakeSessionRepo) Create(_ context.Context, p repository.CreateSessionParams) (*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	now := f.now()
	s := &domain.Session{
		ID: fmt.Sprintf("sess-%d", f.seq), RealmID: p.RealmID, UserID: p.UserID,
		CreatedAt: now, LastActivityAt: now, ExpiresAt: p.ExpiresAt,
		IPAddress: p.IPAddress, UserAgent: p.UserAgent,
		MFAVerified: p.MFAVerified, MFAMethodType: p.MFAMethodType, AuthMethod: p.AuthMethod,
		Status: domain.SessionActive, TokenHash: p.TokenHash,
	}
	f.byID[s.ID] = s
	cp := *s
	return &cp, nil
}

func (f *fakeSessionRepo) GetByID(_ context.Context, id string) (*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.byID[id]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeSessionRepo) GetByTokenHash(_ context.Context, hash string) (*domain.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.TokenHash == hash {
			cp := *s
			return &cp, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *fakeSessionRepo) Touch(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[id].LastActivityAt = at
	return nil
}

func (f *fakeSessionRepo) MarkExpired(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[id].Status = domain.SessionExpired
	return nil
}

func (f *fakeSessionRepo) Revoke(_ context.Context, id string, reason domain.SessionRevokedReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return repository.ErrNotFound
	}
	s.Status, s.RevokedReason = domain.SessionRevoked, reason
	return nil
}

// fakeSettingsRepo always misses: SessionService falls back to its defaults
// (8h absolute, 10 min idle).
type fakeSettingsRepo struct {
	repository.InstanceSettingsRepository
}

func (fakeSettingsRepo) GetByRealmID(context.Context, string) (*domain.InstanceSettings, error) {
	return nil, repository.ErrNotFound
}

// fakeSessionCache is an always-empty cache: every lookup goes to the repo.
type fakeSessionCache struct{}

func (fakeSessionCache) Get(context.Context, string) (sessioncache.Result, error) {
	return sessioncache.Result{}, nil
}
func (fakeSessionCache) Fill(context.Context, string, sessioncache.Entry, time.Duration) error {
	return nil
}
func (fakeSessionCache) Refresh(context.Context, string, sessioncache.Entry, time.Duration) error {
	return nil
}
func (fakeSessionCache) MarkRevoked(context.Context, string, time.Duration) error { return nil }

type fakeClientAppRepo struct {
	repository.ClientRepository
	byID map[string]*domain.ClientApp
}

func (f *fakeClientAppRepo) GetByID(_ context.Context, id string) (*domain.ClientApp, error) {
	if c, ok := f.byID[id]; ok {
		return c, nil
	}
	return nil, repository.ErrNotFound
}

type fakeTokenRepo struct {
	repository.TokenRepository
	byJTI map[string]*domain.Token
}

func (f *fakeTokenRepo) GetByJTI(_ context.Context, jti string) (*domain.Token, error) {
	if t, ok := f.byJTI[jti]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *fakeTokenRepo) Revoke(_ context.Context, id string) error {
	for _, t := range f.byJTI {
		if t.ID == id {
			t.Revoked = true
			return nil
		}
	}
	return repository.ErrNotFound
}

type fakeSigningKeyRepo struct {
	repository.SigningKeyRepository
	keys []*domain.SigningKey
}

func (f *fakeSigningKeyRepo) ListActiveByRealm(_ context.Context, realmID string) ([]*domain.SigningKey, error) {
	var out []*domain.SigningKey
	for _, k := range f.keys {
		if k.RealmID == realmID && k.Status != domain.SigningKeyRetired {
			out = append(out, k)
		}
	}
	return out, nil
}

// fakeTimeouts blocks every call while blocked is true.
type fakeTimeouts struct{ blocked bool }

func (f *fakeTimeouts) HasActiveTimeout(context.Context, string, string) (bool, error) {
	return f.blocked, nil
}

// --- fixture ---------------------------------------------------------------

const (
	alicePassword = "correct horse battery staple"
	aliceID       = "user-alice"
	clientOIDC    = "client-oidc"
	clientSAML    = "client-saml"
	clientLongTTL = "client-long-ttl"
	clientNoAud   = "client-no-audience"
	clientOther   = "client-other"
)

// Argon2id is deliberately slow (~300 ms): hash once for the whole package.
var (
	aliceHashOnce sync.Once
	aliceHash     string
)

func alicePasswordHash(t *testing.T) string {
	t.Helper()
	aliceHashOnce.Do(func() {
		h, err := service.HashPassword(alicePassword)
		if err != nil {
			panic(err)
		}
		aliceHash = h
	})
	return aliceHash
}

type coreFixture struct {
	core     *service.IdentityCoreService
	now      time.Time
	attempts *fakeLoginAttemptRepo
	sessions *fakeSessionRepo
	audit    *fakeAuditRepo
	tokens   *fakeTokenRepo
	keys     *fakeSigningKeyRepo
	km       *localdev.KeyManager
	timeouts *fakeTimeouts
}

// advance moves the shared fake clock forward.
func (f *coreFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func newCoreFixture(t *testing.T) *coreFixture {
	t.Helper()
	f := &coreFixture{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }

	users := &fakeUserRepo{byID: map[string]*domain.User{
		aliceID: {
			ID: aliceID, RealmID: realmA, Username: "alice", Email: "alice@example.com",
			PasswordHash: alicePasswordHash(t), Status: domain.UserActive,
		},
	}}

	// RBAC data (helpers from rbac_test.go): alice holds "role-app", which
	// grants the "profile" and "email" scopes.
	profile, email := scope("s-profile", "profile"), scope("s-email", "email")
	allowed := []string{"role-app"}
	scopeIDs := []string{"s-profile", "s-email"}
	access := &fakeAccessRepo{
		users: map[string]*domain.UserAccess{
			aliceID: activeUser(aliceID, []domain.AccessSource{
				role("role-app", nil, []*domain.ClientScope{profile, email}),
			}, nil),
		},
		clients: map[string]*domain.ClientAccessPolicy{
			clientOIDC:    activeClient(clientOIDC, allowed, nil, scopeIDs),
			clientSAML:    activeClient(clientSAML, allowed, nil, scopeIDs),
			clientLongTTL: activeClient(clientLongTTL, allowed, nil, scopeIDs),
			clientNoAud:   activeClient(clientNoAud, allowed, nil, scopeIDs),
			clientOther:   activeClient(clientOther, []string{"role-someone-else"}, nil, nil),
		},
	}

	clients := &fakeClientAppRepo{byID: map[string]*domain.ClientApp{
		clientOIDC: {ID: clientOIDC, RealmID: realmA, Protocol: domain.ClientAppProtocolOIDC,
			Status: domain.ClientAppActive, ClientID: "app-public-id", IDTokenTTL: 3600},
		clientSAML: {ID: clientSAML, RealmID: realmA, Protocol: domain.ClientAppProtocolSAML2,
			Status: domain.ClientAppActive, EntityID: "https://sp.example.com/metadata", IDTokenTTL: 3600},
		clientLongTTL: {ID: clientLongTTL, RealmID: realmA, Protocol: domain.ClientAppProtocolOIDC,
			Status: domain.ClientAppActive, ClientID: "long-ttl-app", IDTokenTTL: 24 * 3600},
		clientNoAud: {ID: clientNoAud, RealmID: realmA, Protocol: domain.ClientAppProtocolOIDC,
			Status: domain.ClientAppActive}, // no ClientID: misconfigured
	}}

	f.attempts = &fakeLoginAttemptRepo{}
	f.sessions = &fakeSessionRepo{now: clock, byID: map[string]*domain.Session{}}
	f.tokens = &fakeTokenRepo{byJTI: map[string]*domain.Token{}}
	f.keys = &fakeSigningKeyRepo{}
	f.km = localdev.New("test") // real in-memory crypto, no mock needed
	f.timeouts = &fakeTimeouts{}

	rbac, audit := newRBAC(access)
	f.audit = audit

	f.core = service.NewIdentityCore(service.IdentityCoreDeps{
		Auth:        service.NewAuthService(users, f.attempts, service.WithTimeoutChecker(f.timeouts)),
		Sessions:    service.NewSessionService(f.sessions, fakeSettingsRepo{}, fakeSessionCache{}, service.WithClock(clock)),
		RBAC:        rbac,
		Users:       users,
		Clients:     clients,
		Tokens:      f.tokens,
		SigningKeys: f.keys,
		KeyManager:  f.km,
		Timeouts:    f.timeouts,
	}, service.WithIdentityCoreClock(clock))
	return f
}

func (f *coreFixture) aliceSession(t *testing.T) *core.IssuedSession {
	t.Helper()
	issued, err := f.core.CreateSession(context.Background(), aliceID, core.AuthContext{
		RealmID: realmA, IPAddress: "203.0.113.7", UserAgent: "test", AuthMethod: "password",
	})
	require.NoError(t, err)
	return issued
}

func (f *coreFixture) addKey(t *testing.T, kt domain.SigningKeyType, purpose domain.SigningKeyPurpose,
	status domain.SigningKeyStatus, kid string, age time.Duration) *domain.SigningKey {
	t.Helper()
	kmType := keymanager.KeyTypeRSA
	if kt == domain.SigningKeyEC {
		kmType = keymanager.KeyTypeEC
	}
	gen, err := f.km.GenerateKey(context.Background(), kmType)
	require.NoError(t, err)
	k := &domain.SigningKey{
		ID: "id-" + kid, RealmID: realmA, KeyType: kt, Purpose: purpose, Status: status,
		KMSKeyReference: gen.KMSKeyReference, PublicKey: gen.PublicKeyPEM, Kid: kid,
		CreatedAt: f.now.Add(-age),
	}
	f.keys.keys = append(f.keys.keys, k)
	return k
}

func parsePublicKey(t *testing.T, pemStr string) any {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return pub
}

// --- tests -----------------------------------------------------------------

func TestIdentityCore_AuthenticateLocal(t *testing.T) {
	ctx := context.Background()

	t.Run("valid credentials return the user", func(t *testing.T) {
		f := newCoreFixture(t)
		u, err := f.core.AuthenticateLocal(ctx, core.Credentials{
			RealmID: realmA, Identifier: "alice", Password: alicePassword,
		})
		require.NoError(t, err)
		require.Equal(t, aliceID, u.ID)
		require.Equal(t, domain.LoginAttemptSuccess, f.attempts.last().Status)
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		f := newCoreFixture(t)
		_, err := f.core.AuthenticateLocal(ctx, core.Credentials{
			RealmID: realmA, Identifier: "alice@example.com", Password: "nope",
		})
		// The service alias and the core error are the same variable.
		require.ErrorIs(t, err, core.ErrInvalidCredentials)
		require.ErrorIs(t, err, service.ErrInvalidCredentials)
	})

	t.Run("active timeout blocks a correct login and is recorded", func(t *testing.T) {
		f := newCoreFixture(t)
		f.timeouts.blocked = true
		_, err := f.core.AuthenticateLocal(ctx, core.Credentials{
			RealmID: realmA, Identifier: "alice", Password: alicePassword,
		})
		require.ErrorIs(t, err, core.ErrTimeoutActive)
		last := f.attempts.last()
		require.Equal(t, domain.LoginAttemptFailure, last.Status)
		require.Equal(t, domain.LoginFailureTimeoutActive, last.FailureReason)
	})
}

func TestIdentityCore_VerifyMFA_NotImplementedYet(t *testing.T) {
	f := newCoreFixture(t)
	ok, err := f.core.VerifyMFA(context.Background(), aliceID, core.MFAChallenge{})
	require.False(t, ok)
	require.ErrorIs(t, err, core.ErrMFANotImplemented)
}

func TestIdentityCore_Sessions(t *testing.T) {
	ctx := context.Background()

	t.Run("raw token is returned once and only its hash is stored", func(t *testing.T) {
		f := newCoreFixture(t)
		issued := f.aliceSession(t)
		require.NotEmpty(t, issued.RawToken)
		require.Equal(t, service.HashSessionToken(issued.RawToken), issued.Session.TokenHash)
		require.NotEqual(t, issued.RawToken, issued.Session.TokenHash)
	})

	t.Run("front-channel (token) and back-channel (id) lookups agree", func(t *testing.T) {
		f := newCoreFixture(t)
		issued := f.aliceSession(t)

		byToken, err := f.core.ValidateSession(ctx, realmA, issued.RawToken)
		require.NoError(t, err)
		byID, err := f.core.GetSession(ctx, issued.Session.ID)
		require.NoError(t, err)
		require.Equal(t, byToken.ID, byID.ID)
	})

	t.Run("revoked session is rejected immediately", func(t *testing.T) {
		f := newCoreFixture(t)
		issued := f.aliceSession(t)
		require.NoError(t, f.core.RevokeSession(ctx, issued.Session.ID, domain.SessionRevokedAdminRevoked))

		_, err := f.core.GetSession(ctx, issued.Session.ID)
		require.ErrorIs(t, err, core.ErrSessionInvalid)
		_, err = f.core.ValidateSession(ctx, realmA, issued.RawToken)
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})

	t.Run("back-channel lookup does not keep an idle session alive", func(t *testing.T) {
		f := newCoreFixture(t)
		issued := f.aliceSession(t)
		for range 3 { // 3 x 4 min of back-channel calls only = 12 min idle
			f.advance(4 * time.Minute)
			_, _ = f.core.GetSession(ctx, issued.Session.ID)
		}
		_, err := f.core.GetSession(ctx, issued.Session.ID)
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})
}

func TestIdentityCore_IssueIdentityAssertion(t *testing.T) {
	ctx := context.Background()

	t.Run("OIDC client: neutral assertion with stable subject", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		a, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientOIDC, nil)
		require.NoError(t, err)
		require.Equal(t, aliceID, a.Subject, "subject must be the user id, never the email")
		require.Equal(t, "app-public-id", a.Audience)
		require.Equal(t, f.now, a.IssuedAt)
		require.Equal(t, f.now.Add(time.Hour), a.ExpiresAt) // id_token_ttl = 3600 s
		require.Equal(t, sess.CreatedAt, a.AuthTime)
		require.Equal(t, "password", a.AuthMethod)
		require.Equal(t, sess.ID, a.SessionID)
		require.Equal(t, "alice@example.com", a.Claims["email"])
		require.Equal(t, "alice", a.Claims["username"])
		require.ElementsMatch(t, []string{"email", "profile"}, scopeNames(a.Scopes))
	})

	t.Run("SAML client: entity id as audience, short default lifetime", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		a, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientSAML, nil)
		require.NoError(t, err)
		require.Equal(t, "https://sp.example.com/metadata", a.Audience)
		require.Equal(t, f.now.Add(5*time.Minute), a.ExpiresAt)
	})

	t.Run("assertion never outlives its session", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session // expires after 8h (default)

		a, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientLongTTL, nil)
		require.NoError(t, err)
		require.Equal(t, sess.ExpiresAt, a.ExpiresAt) // 24h TTL capped to 8h
	})

	t.Run("requested scopes narrow the result but never grant", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		a, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientOIDC, []string{"email", "admin"})
		require.NoError(t, err)
		require.Equal(t, []string{"email"}, scopeNames(a.Scopes))
	})

	t.Run("client the user is not allowed on is refused and audited", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		_, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientOther, nil)
		require.ErrorIs(t, err, core.ErrForbidden)
		require.Len(t, f.audit.entries, 1)
		require.Equal(t, "authorization_denied", f.audit.entries[0].Action)
		require.Equal(t, aliceID, f.audit.entries[0].UserID)
	})

	t.Run("revoked session cannot produce an assertion", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		require.NoError(t, f.core.RevokeSession(ctx, sess.ID, domain.SessionRevokedUserLogout))

		_, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrSessionInvalid)
	})

	t.Run("active timeout blocks the assertion", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session
		f.timeouts.blocked = true

		_, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientOIDC, nil)
		require.ErrorIs(t, err, core.ErrTimeoutActive)
	})

	t.Run("client without audience identifier is reported as misconfigured", func(t *testing.T) {
		f := newCoreFixture(t)
		sess := f.aliceSession(t).Session

		_, err := f.core.IssueIdentityAssertion(ctx, sess.ID, clientNoAud, nil)
		require.ErrorIs(t, err, core.ErrClientMisconfigured)
	})
}

func TestIdentityCore_IsAuthorizedForClient(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)

	ok, err := f.core.IsAuthorizedForClient(ctx, aliceID, clientOIDC)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = f.core.IsAuthorizedForClient(ctx, aliceID, clientOther)
	require.NoError(t, err)
	require.False(t, ok)

	f.timeouts.blocked = true
	ok, err = f.core.IsAuthorizedForClient(ctx, aliceID, clientOIDC)
	require.NoError(t, err)
	require.False(t, ok, "an active timeout must deny access")
}

func TestIdentityCore_Tokens(t *testing.T) {
	ctx := context.Background()
	f := newCoreFixture(t)
	f.tokens.byJTI["jti-1"] = &domain.Token{ID: "tok-1", JTI: "jti-1"}

	revoked, err := f.core.IsTokenRevoked(ctx, "jti-unknown")
	require.NoError(t, err)
	require.True(t, revoked, "unknown jti must fail closed")

	revoked, err = f.core.IsTokenRevoked(ctx, "jti-1")
	require.NoError(t, err)
	require.False(t, revoked)

	require.NoError(t, f.core.RevokeToken(ctx, "jti-1"))
	revoked, err = f.core.IsTokenRevoked(ctx, "jti-1")
	require.NoError(t, err)
	require.True(t, revoked)

	require.NoError(t, f.core.RevokeToken(ctx, "jti-1"), "revoking twice is fine")
	require.NoError(t, f.core.RevokeToken(ctx, "jti-unknown"), "revoking an unknown jti is fine")
}

func TestIdentityCore_Signer(t *testing.T) {
	ctx := context.Background()
	payload := []byte("header.payload")
	digest := sha256.Sum256(payload)

	t.Run("no active key for that purpose", func(t *testing.T) {
		f := newCoreFixture(t)
		f.addKey(t, domain.SigningKeyRSA, domain.SigningKeyPurposeSAMLSigning, domain.SigningKeyActive, "saml-1", 0)

		_, err := f.core.Signer(ctx, realmA, domain.SigningKeyPurposeJWT)
		require.ErrorIs(t, err, core.ErrNoActiveSigningKey)
	})

	t.Run("picks the newest active key, kid known before signing (RSA)", func(t *testing.T) {
		f := newCoreFixture(t)
		f.addKey(t, domain.SigningKeyRSA, domain.SigningKeyPurposeJWT, domain.SigningKeyActive, "jwt-old", 48*time.Hour)
		want := f.addKey(t, domain.SigningKeyRSA, domain.SigningKeyPurposeJWT, domain.SigningKeyActive, "jwt-new", time.Hour)
		// Newer but rotating: valid for verification, must not sign.
		f.addKey(t, domain.SigningKeyRSA, domain.SigningKeyPurposeJWT, domain.SigningKeyRotating, "jwt-rotating", 0)

		signer, err := f.core.Signer(ctx, realmA, domain.SigningKeyPurposeJWT)
		require.NoError(t, err)
		require.Equal(t, "jwt-new", signer.KeyID()) // available BEFORE Sign
		require.Equal(t, domain.SigningKeyRSA, signer.KeyType())

		sig, err := signer.Sign(ctx, payload)
		require.NoError(t, err)
		pub, ok := parsePublicKey(t, want.PublicKey).(*rsa.PublicKey)
		require.True(t, ok)
		require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
	})

	t.Run("EC key signature verifies with the stored public key", func(t *testing.T) {
		f := newCoreFixture(t)
		want := f.addKey(t, domain.SigningKeyEC, domain.SigningKeyPurposeJWT, domain.SigningKeyActive, "jwt-ec", 0)

		signer, err := f.core.Signer(ctx, realmA, domain.SigningKeyPurposeJWT)
		require.NoError(t, err)
		require.Equal(t, domain.SigningKeyEC, signer.KeyType())

		sig, err := signer.Sign(ctx, payload)
		require.NoError(t, err)
		pub, ok := parsePublicKey(t, want.PublicKey).(*ecdsa.PublicKey)
		require.True(t, ok)
		require.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
	})
}
