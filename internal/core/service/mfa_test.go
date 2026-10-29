package service_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/mfastore"
	"sso.internal/sso/internal/passkey"
	"sso.internal/sso/internal/storage/memstore"
)



type mfaSettingsRepo struct {
	repository.InstanceSettingsRepository
	mu     sync.Mutex
	byRelm map[string]*domain.InstanceSettings
}

func (f *mfaSettingsRepo) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.byRelm[realmID]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *mfaSettingsRepo) Create(_ context.Context, p repository.CreateInstanceSettingsParams) (*domain.InstanceSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &domain.InstanceSettings{ID: "settings-" + p.RealmID, RealmID: p.RealmID, ManagedBy: domain.InstanceSettingsManagedByUI, MFAStepUpMaxAgeMinutes: 10,
		MFATrustedDeviceEnabled: true, MFATrustedDeviceDays: 30} // the database defaults
	f.byRelm[p.RealmID] = s
	cp := *s
	return &cp, nil
}

func (f *mfaSettingsRepo) Update(_ context.Context, id string, p repository.UpdateInstanceSettingsParams) (*domain.InstanceSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byRelm {
		if s.ID != id {
			continue
		}
		if p.MFARequiredGlobally != nil {
			s.MFARequiredGlobally = *p.MFARequiredGlobally
		}
		if p.MFAStepUpMaxAgeMinutes != nil {
			s.MFAStepUpMaxAgeMinutes = *p.MFAStepUpMaxAgeMinutes
		}
		if p.MFATrustedDeviceEnabled != nil {
			s.MFATrustedDeviceEnabled = *p.MFATrustedDeviceEnabled
		}
		if p.MFATrustedDeviceDays != nil {
			s.MFATrustedDeviceDays = *p.MFATrustedDeviceDays
		}
		cp := *s
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *mfaSettingsRepo) set(realmID string, mod func(*domain.InstanceSettings)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byRelm[realmID]
	if !ok {
		s = &domain.InstanceSettings{ID: "settings-" + realmID, RealmID: realmID, MFAStepUpMaxAgeMinutes: 10,
			MFATrustedDeviceEnabled: true, MFATrustedDeviceDays: 30}
		f.byRelm[realmID] = s
	}
	mod(s)
}

// mfaClientRepo: GetByID + Update of the MFA fields.
type mfaClientRepo struct {
	repository.ClientRepository
	mu   sync.Mutex
	byID map[string]*domain.ClientApp
}

func (f *mfaClientRepo) GetByID(_ context.Context, id string) (*domain.ClientApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.byID[id]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, repository.ErrNotFound
}

func (f *mfaClientRepo) Update(_ context.Context, id string, p repository.UpdateClientAppParams) (*domain.ClientApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.byID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if p.MFAPolicy != nil {
		c.MFAPolicy = *p.MFAPolicy
	}
	if p.MFAAllowedMethods != nil {
		c.MFAAllowedMethods = p.MFAAllowedMethods
		if len(c.MFAAllowedMethods) == 0 {
			c.MFAAllowedMethods = nil
		}
	}
	cp := *c
	return &cp, nil
}

type mfaRoleRepo struct {
	repository.RoleRepository
	roles []*domain.Role
}

func (f *mfaRoleRepo) GetByRealmAndName(_ context.Context, realmID, name string) (*domain.Role, error) {
	for _, r := range f.roles {
		if r.RealmID == realmID && r.Name == name {
			return r, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (f *mfaRoleRepo) GetByID(_ context.Context, id string) (*domain.Role, error) {
	for _, r := range f.roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, repository.ErrNotFound
}

// countingLimiter allows `limit` calls per key, then refuses.
type countingLimiter struct {
	mu    sync.Mutex
	limit int64
	seen  map[string]int64
}

func (l *countingLimiter) Allow(_ context.Context, key string, _ int64, _ time.Duration) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen[key]++
	return l.seen[key] <= l.limit, nil
}

// --- fixture -------------------------------------------------------------------

const (
	mfaClientPlain   = "client-plain"
	mfaClientStrict  = "client-strict"  // mfa required
	mfaClientPasskey = "client-passkey" // mfa required, passkey only
	roleAdminID      = "role-admin"
)

type mfaFixture struct {
	now        time.Time
	mfa        *service.MFAService
	policy     *service.MFAPolicyService
	sessions   *fakeSessionRepo
	sessionSvc *service.SessionService
	methods    *memstore.MfaMethods
	codes      *memstore.MfaBackupCodes
	policies   *memstore.MfaPolicies
	keys       *memstore.SigningKeys
	settings   *mfaSettingsRepo
	clients    *mfaClientRepo
	access     *fakeAccessRepo
	attempts   *fakeLoginAttemptRepo
	audit      *fakeAuditRepo
	limiter    *countingLimiter
	users      *fakeUserRepo
	core       *service.IdentityCoreService
	passkeys   service.PasskeyProvider
	notifier   *recordingNotifier
	// "Don't ask again on this device" (Step 18d).
	devices *memstore.TrustedDevices
	trusted *service.TrustedDeviceService
	risk    *fakeRisk
	// How the user likes to sign in on a device (Step 18e).
	known    *fakeKnownAccounts
	accounts *service.KnownAccountService
}

// Relying party used by the passkey tests (the software authenticator of
// internal/passkey/passkeytest answers from this origin).
const (
	testRPID   = "sso.test"
	testOrigin = "https://sso.test"
)

func (f *mfaFixture) clock() time.Time        { return f.now }
func (f *mfaFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	f := &mfaFixture{now: time.Date(2026, 10, 17, 9, 0, 15, 0, time.UTC)}
	clock := f.clock

	f.users = &fakeUserRepo{byID: map[string]*domain.User{
		aliceID: {ID: aliceID, RealmID: realmA, Username: "alice", Email: "alice@example.com",
			PasswordHash: alicePasswordHash(t), Status: domain.UserActive, CreatedAt: f.now.Add(-365 * 24 * time.Hour)},
		bobID: {ID: bobID, RealmID: realmA, Username: "bob", Status: domain.UserActive, CreatedAt: f.now.Add(-365 * 24 * time.Hour)},
	}}
	f.sessions = &fakeSessionRepo{now: clock, byID: map[string]*domain.Session{}}
	f.sessionSvc = service.NewSessionService(f.sessions, fakeSettingsRepo{}, &fakeTokenRepo{byJTI: map[string]*domain.Token{}}, fakeSessionCache{}, service.WithClock(clock))
	f.methods = memstore.NewMfaMethods(clock)
	f.codes = memstore.NewMfaBackupCodes(clock)
	f.policies = memstore.NewMfaPolicies(clock)
	f.keys = memstore.NewSigningKeys(clock)
	f.settings = &mfaSettingsRepo{byRelm: map[string]*domain.InstanceSettings{}}
	f.attempts = &fakeLoginAttemptRepo{}
	f.audit = &fakeAuditRepo{}
	f.limiter = &countingLimiter{limit: 1000, seen: map[string]int64{}}
	f.notifier = &recordingNotifier{}

	appRole := role("role-app", nil, nil)
	f.access = &fakeAccessRepo{
		users: map[string]*domain.UserAccess{
			aliceID: activeUser(aliceID, []domain.AccessSource{appRole}, nil),
			bobID:   activeUser(bobID, []domain.AccessSource{appRole}, nil),
		},
		clients: map[string]*domain.ClientAccessPolicy{},
	}
	for _, ref := range []string{mfaClientPlain, mfaClientStrict, mfaClientPasskey} {
		f.access.clients[ref] = activeClient(ref, []string{"role-app"}, nil, nil)
	}

	oidc := func(id string, policy domain.ClientAppMFAPolicy, methods ...domain.MfaMethodType) *domain.ClientApp {
		return &domain.ClientApp{ID: id, RealmID: realmA, Protocol: domain.ClientAppProtocolOIDC, Status: domain.ClientAppActive,
			ClientID: id + "-id", IDTokenTTL: 300, SubjectType: domain.ClientAppSubjectPublic,
			MFAPolicy: policy, MFAAllowedMethods: methods}
	}
	f.clients = &mfaClientRepo{byID: map[string]*domain.ClientApp{
		mfaClientPlain:   oidc(mfaClientPlain, domain.ClientAppMFAInherit),
		mfaClientStrict:  oidc(mfaClientStrict, domain.ClientAppMFARequired),
		mfaClientPasskey: oidc(mfaClientPasskey, domain.ClientAppMFARequired, domain.MfaMethodPasskey),
	}}

	f.policy = service.NewMFAPolicyService(service.MFAPolicyDeps{
		Settings: f.settings,
		Clients:  f.clients,
		Roles:    &mfaRoleRepo{roles: []*domain.Role{{ID: roleAdminID, RealmID: realmA, Name: "admin"}, {ID: "role-app", RealmID: realmA, Name: "app"}}},
		Policies: f.policies,
		Access:   f.access,
		Audit:    f.audit,
		Now:      clock,
	})
	pk, err := passkey.New(passkey.Config{RPID: testRPID, RPOrigins: []string{testOrigin}})
	require.NoError(t, err)
	f.passkeys = pk

	f.devices = memstore.NewTrustedDevices()
	f.trusted = service.NewTrustedDeviceService(service.TrustedDeviceDeps{Devices: f.devices, Settings: f.settings, Audit: f.audit, Now: clock})
	f.risk = &fakeRisk{}
	f.known = newFakeKnownAccounts()
	f.accounts = service.NewKnownAccountService(service.KnownAccountDeps{Accounts: f.known, Users: f.users, Now: clock})
	f.mfa = service.NewMFAService(service.MFADeps{
		Users:         f.users,
		Methods:       f.methods,
		BackupCodes:   f.codes,
		Sessions:      f.sessionSvc,
		Policy:        f.policy,
		Envelope:      service.NewEnvelopeService(f.keys, localdev.New("test"), "local_dev"),
		Store:         mfastore.NewMemory(clock),
		Limiter:       f.limiter,
		LoginAttempts: f.attempts,
		Audit:         f.audit,
		Clients:       f.clients,
		Passkeys:      f.passkeys,
		Notifier:      f.notifier,
		IssuerName:    "Oh-My-SSO test",
		Now:           clock,
		// Off until a test gives a device fingerprint.
		TrustedDevices: f.trusted,
		Risk:           f.risk,
		Memory:         f.accounts,
	})

	rbac, _ := newRBAC(f.access)
	f.core = service.NewIdentityCore(service.IdentityCoreDeps{
		Auth:        service.NewAuthService(f.users, f.attempts),
		Sessions:    f.sessionSvc,
		RBAC:        rbac,
		Users:       f.users,
		Clients:     f.clients,
		Realms:      &fakeRealmRepo{salts: map[string]string{}},
		Tokens:      &fakeTokenRepo{byJTI: map[string]*domain.Token{}},
		SigningKeys: &fakeSigningKeyRepo{},
		KeyManager:  localdev.New("test"),
		MFA:         f.mfa,
	}, service.WithIdentityCoreClock(clock))
	return f
}

func (f *mfaFixture) user(id string) *domain.User {
	u, _ := f.users.GetByID(context.Background(), id)
	return u
}

// passwordSession creates a session as a plain password login does.
func (f *mfaFixture) passwordSession(t *testing.T, userID string) *domain.Session {
	t.Helper()
	_, sess, err := f.sessionSvc.Create(context.Background(), service.CreateSessionInput{
		RealmID: realmA, UserID: userID, AuthMethod: domain.AuthMethodPassword,
	})
	require.NoError(t, err)
	return sess
}

// totpAt computes the code an authenticator app shows at time at.
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)
	return code
}

// enrollTOTP runs the whole enrollment and returns the secret and the
// backup codes. The clock moves 30 s forward so the confirmation code
// cannot collide with codes the test uses right after.
func (f *mfaFixture) enrollTOTP(t *testing.T, userID string) (string, []string) {
	t.Helper()
	ctx := context.Background()
	sess := f.passwordSession(t, userID)
	enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(userID), "phone")
	require.NoError(t, err)
	res, err := f.mfa.ConfirmTOTPEnrollment(ctx, f.user(userID), sess, enr.MethodID, totpAt(t, enr.Secret, f.now))
	require.NoError(t, err)
	f.advance(30 * time.Second)
	return enr.Secret, res.BackupCodes
}

func (f *mfaFixture) beginLogin(t *testing.T, userID, clientRef string) *service.LoginDecision {
	t.Helper()
	var client *domain.ClientApp
	if clientRef != "" {
		client, _ = f.clients.GetByID(context.Background(), clientRef)
	}
	dec, err := f.mfa.BeginLogin(context.Background(), service.BeginLoginInput{User: f.user(userID), Client: client, IPAddress: "203.0.113.9", UserAgent: "test"})
	require.NoError(t, err)
	return dec
}

func (f *mfaFixture) verify(dec *service.LoginDecision, method, code string) (*service.VerifiedLogin, error) {
	return f.mfa.VerifyLogin(context.Background(), service.VerifyLoginInput{
		RealmID: realmA, ChallengeToken: dec.ChallengeToken, Method: method, Code: code,
		IPAddress: "203.0.113.9", UserAgent: "test",
	})
}

// --- tests -----------------------------------------------------------------------

func TestMFA_TOTPEnrollment(t *testing.T) {
	ctx := context.Background()

	t.Run("pending factor is not usable, confirmation activates it", func(t *testing.T) {
		f := newMFAFixture(t)
		sess := f.passwordSession(t, aliceID)

		enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(aliceID), "Pixel 9")
		require.NoError(t, err)
		require.Len(t, enr.Secret, 32, "160-bit secret = 32 base32 characters")
		require.True(t, strings.HasPrefix(enr.URI, "otpauth://totp/Oh-My-SSO%20test:alice?"), enr.URI)
		require.Contains(t, enr.URI, "issuer=Oh-My-SSO%20test")
		require.True(t, strings.HasPrefix(enr.QRCodePNG, "data:image/png;base64,"))
		require.Equal(t, f.now.Add(10*time.Minute), enr.ExpiresAt)

		stored, err := f.methods.GetByID(ctx, enr.MethodID)
		require.NoError(t, err)
		require.Equal(t, domain.MfaMethodPending, stored.Status)
		require.NotContains(t, stored.SecretEncrypted, enr.Secret, "the secret is never stored in clear")

		dec := f.beginLogin(t, aliceID, "")
		require.Equal(t, service.LoginAuthenticated, dec.Outcome, "a pending factor never triggers a challenge")

		_, err = f.mfa.ConfirmTOTPEnrollment(ctx, f.user(aliceID), sess, enr.MethodID, "000000")
		require.ErrorIs(t, err, service.ErrInvalidMFACode)

		res, err := f.mfa.ConfirmTOTPEnrollment(ctx, f.user(aliceID), sess, enr.MethodID, totpAt(t, enr.Secret, f.now))
		require.NoError(t, err)
		require.Equal(t, domain.MfaMethodActive, res.Method.Status)
		require.Equal(t, "Pixel 9", res.Method.Name)
		require.Len(t, res.BackupCodes, 10, "first factor: backup codes generated and shown once")
		require.True(t, res.Session.MFAVerified, "confirming with a fresh code verifies the session")
		require.Equal(t, "totp", res.Session.MFAMethodType)
		require.Equal(t, f.now, res.Session.MFAVerifiedAt)
		require.Equal(t, "mfa_method_enrolled", f.audit.entries[len(f.audit.entries)-1].Action)
	})

	t.Run("expired enrollment", func(t *testing.T) {
		f := newMFAFixture(t)
		enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(aliceID), "")
		require.NoError(t, err)
		f.advance(11 * time.Minute)
		_, err = f.mfa.ConfirmTOTPEnrollment(ctx, f.user(aliceID), nil, enr.MethodID, totpAt(t, enr.Secret, f.now))
		require.ErrorIs(t, err, service.ErrMFAEnrollmentExpired)
	})

	t.Run("another user's enrollment looks like it does not exist", func(t *testing.T) {
		f := newMFAFixture(t)
		enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(aliceID), "")
		require.NoError(t, err)
		_, err = f.mfa.ConfirmTOTPEnrollment(ctx, f.user(bobID), nil, enr.MethodID, totpAt(t, enr.Secret, f.now))
		require.ErrorIs(t, err, service.ErrMFAMethodNotFound)
	})

	t.Run("new phone replaces the old TOTP, backup codes are kept", func(t *testing.T) {
		f := newMFAFixture(t)
		oldSecret, codes := f.enrollTOTP(t, aliceID)

		enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(aliceID), "new phone")
		require.NoError(t, err)
		res, err := f.mfa.ConfirmTOTPEnrollment(ctx, f.user(aliceID), nil, enr.MethodID, totpAt(t, enr.Secret, f.now))
		require.NoError(t, err)
		require.Empty(t, res.BackupCodes, "not the first factor: existing codes stay valid")

		list, err := f.mfa.ListFactors(ctx, aliceID)
		require.NoError(t, err)
		require.Len(t, list.Methods, 1)
		require.Equal(t, "new phone", list.Methods[0].Name)
		require.Equal(t, 10, list.BackupCodes.Remaining)

		f.advance(30 * time.Second)
		dec := f.beginLogin(t, aliceID, "")
		_, err = f.verify(dec, "totp", totpAt(t, oldSecret, f.now))
		require.ErrorIs(t, err, service.ErrInvalidMFACode, "the old phone no longer works")
		_, err = f.verify(dec, "backup_code", codes[0])
		require.NoError(t, err)
	})
}

// TestMFA_DefinitionOfDone: enrollment TOTP -> login with a correct TOTP ->
// login with a backup code -> login with an expired / invalid TOTP rejected.
func TestMFA_DefinitionOfDone(t *testing.T) {
	f := newMFAFixture(t)
	secret, codes := f.enrollTOTP(t, aliceID)

	// 1. Correct TOTP.
	before := len(f.sessionsOf(aliceID, false))
	dec := f.beginLogin(t, aliceID, "")
	require.Equal(t, service.LoginMFARequired, dec.Outcome)
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodBackupCodes}, dec.Methods)
	require.NotEmpty(t, dec.ChallengeToken)
	require.Len(t, f.sessionsOf(aliceID, false), before, "no session at all before the second factor")

	good := totpAt(t, secret, f.now)
	res, err := f.verify(dec, "totp", good)
	require.NoError(t, err)
	require.Equal(t, service.LoginAuthenticated, res.Outcome)
	require.NotEmpty(t, res.RawToken)
	require.True(t, res.Session.MFAVerified)
	require.Equal(t, "totp", res.Session.MFAMethodType)
	require.Equal(t, f.now, res.Session.MFAVerifiedAt)

	// The challenge is single-use.
	_, err = f.verify(dec, "totp", good)
	require.ErrorIs(t, err, service.ErrMFAChallengeInvalid)

	// 2. Same code again on a new challenge: replay refused.
	dec = f.beginLogin(t, aliceID, "")
	_, err = f.verify(dec, "totp", good)
	require.ErrorIs(t, err, service.ErrInvalidMFACode, "a TOTP code can only be used once")

	// 3. Backup code (typed in lower case with spaces): accepted once.
	res, err = f.verify(dec, "backup_code", strings.ToLower(strings.ReplaceAll(codes[3], "-", " ")))
	require.NoError(t, err)
	require.Equal(t, "backup_codes", res.Session.MFAMethodType)
	require.Equal(t, 9, res.BackupCodesRemaining)

	dec = f.beginLogin(t, aliceID, "")
	_, err = f.verify(dec, "backup_code", codes[3])
	require.ErrorIs(t, err, service.ErrInvalidMFACode, "a backup code works once")

	// 4. Expired TOTP (shown two windows ago) and garbage: rejected, and the
	//    tries left go down.
	var codeErr *service.MFACodeError
	_, err = f.verify(dec, "totp", totpAt(t, secret, f.now.Add(-time.Minute)))
	require.ErrorAs(t, err, &codeErr)
	require.Equal(t, 3, codeErr.AttemptsRemaining) // 2 tries used on this challenge already
	_, err = f.verify(dec, "totp", "123456")
	require.ErrorAs(t, err, &codeErr)
	require.Equal(t, 2, codeErr.AttemptsRemaining)
	require.Equal(t, domain.LoginFailureMfaFailed, f.attempts.last().FailureReason)

	// 5. Five tries max per challenge, then back to the password.
	_, _ = f.verify(dec, "totp", "123456")
	_, _ = f.verify(dec, "totp", "123456")
	_, err = f.verify(dec, "totp", totpAt(t, secret, f.now))
	require.ErrorIs(t, err, service.ErrMFAChallengeInvalid, "even a good code is refused after 5 tries")

	// 6. A method that cannot answer the challenge.
	dec = f.beginLogin(t, aliceID, "")
	_, err = f.verify(dec, "sms", "123456")
	require.ErrorIs(t, err, service.ErrMFAMethodNotAllowed)

	// 7. An expired challenge.
	f.advance(6 * time.Minute)
	_, err = f.verify(dec, "totp", totpAt(t, secret, f.now))
	require.ErrorIs(t, err, service.ErrMFAChallengeInvalid)
}

func (f *mfaFixture) sessionsOf(userID string, mfaOnly bool) []*domain.Session {
	f.sessions.mu.Lock()
	defer f.sessions.mu.Unlock()
	var out []*domain.Session
	for _, s := range f.sessions.byID {
		if s.UserID == userID && (!mfaOnly || s.MFAVerified) {
			out = append(out, s)
		}
	}
	return out
}

func TestMFA_LoginPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("no factor, nothing required: plain login", func(t *testing.T) {
		f := newMFAFixture(t)
		dec := f.beginLogin(t, bobID, mfaClientPlain)
		require.Equal(t, service.LoginAuthenticated, dec.Outcome)
	})

	t.Run("no factor, client requires MFA: enrollment required", func(t *testing.T) {
		f := newMFAFixture(t)
		dec := f.beginLogin(t, bobID, mfaClientStrict)
		require.Equal(t, service.LoginMFAEnrollmentRequired, dec.Outcome)
		require.Equal(t, []string{"client:client-strict-id"}, dec.Requirement.Sources)
	})

	t.Run("no factor, realm requires MFA: enrollment required", func(t *testing.T) {
		f := newMFAFixture(t)
		f.settings.set(realmA, func(s *domain.InstanceSettings) { s.MFARequiredGlobally = true })
		require.Equal(t, service.LoginMFAEnrollmentRequired, f.beginLogin(t, bobID, "").Outcome)
	})

	t.Run("user with a factor is always challenged, even when optional", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		require.Equal(t, service.LoginMFARequired, f.beginLogin(t, aliceID, mfaClientPlain).Outcome)
	})

	t.Run("role policy with grace: not blocking yet, due date reported", func(t *testing.T) {
		f := newMFAFixture(t)
		f.access.users[bobID] = activeUser(bobID, []domain.AccessSource{namedRole(roleAdminID, "admin")}, nil)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{
			RealmID: realmA, RoleName: "admin", Required: true, EnrollmentGraceDays: 7,
		})
		require.NoError(t, err)

		dec := f.beginLogin(t, bobID, "")
		require.Equal(t, service.LoginAuthenticated, dec.Outcome)
		require.Equal(t, f.now.Add(7*24*time.Hour), dec.Requirement.EnrollmentDueAt)

		f.advance(8 * 24 * time.Hour)
		dec = f.beginLogin(t, bobID, "")
		require.Equal(t, service.LoginMFAEnrollmentRequired, dec.Outcome)
		require.Equal(t, []string{"role:admin"}, dec.Requirement.Sources)
	})

	t.Run("an inactive role requires nothing", func(t *testing.T) {
		f := newMFAFixture(t)
		r := namedRole(roleAdminID, "admin")
		r.Active = false
		f.access.users[bobID] = activeUser(bobID, []domain.AccessSource{r}, nil)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin", Required: true})
		require.NoError(t, err)
		require.Equal(t, service.LoginAuthenticated, f.beginLogin(t, bobID, "").Outcome)
	})

	t.Run("required method missing: challenged with what the user has, then told to enroll", func(t *testing.T) {
		f := newMFAFixture(t)
		secret, _ := f.enrollTOTP(t, aliceID)

		dec := f.beginLogin(t, aliceID, mfaClientPasskey)
		require.Equal(t, service.LoginMFARequired, dec.Outcome)
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodBackupCodes}, dec.Methods)

		res, err := f.verify(dec, "totp", totpAt(t, secret, f.now))
		require.NoError(t, err)
		require.Equal(t, service.LoginMFAEnrollmentRequired, res.Outcome)
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey}, res.Requirement.AllowedMethods)
	})

	t.Run("required with allowed methods: challenge restricted to them", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		f.clients.byID[mfaClientStrict].MFAAllowedMethods = []domain.MfaMethodType{domain.MfaMethodTOTP}
		dec := f.beginLogin(t, aliceID, mfaClientStrict)
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP}, dec.Methods, "backup codes not accepted by this client")
	})

	t.Run("conflicting policies are reported, not guessed", func(t *testing.T) {
		f := newMFAFixture(t)
		f.access.users[bobID] = activeUser(bobID, []domain.AccessSource{namedRole(roleAdminID, "admin")}, nil)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{
			RealmID: realmA, RoleName: "admin", AllowedMethods: []domain.MfaMethodType{domain.MfaMethodTOTP},
		})
		require.NoError(t, err)
		client, _ := f.clients.GetByID(ctx, mfaClientPasskey)
		_, err = f.mfa.BeginLogin(ctx, service.BeginLoginInput{User: f.user(bobID), Client: client})
		require.ErrorIs(t, err, service.ErrMFAPolicyConflict)
	})
}

func namedRole(id, name string) domain.AccessSource {
	r := role(id, nil, nil)
	r.Name = name
	return r
}

func TestMFA_StepUp(t *testing.T) {
	ctx := context.Background()

	t.Run("account security, user without factor: a fresh login is enough", func(t *testing.T) {
		f := newMFAFixture(t)
		sess := f.passwordSession(t, bobID)
		require.NoError(t, f.mfa.CheckStepUp(ctx, sess, service.StepUpAccountSecurity))

		f.advance(11 * time.Minute)
		var su *service.StepUpRequiredError
		require.ErrorAs(t, f.mfa.CheckStepUp(ctx, sess, service.StepUpAccountSecurity), &su)
		require.Equal(t, service.StepUpNeedRecentLogin, su.Reason)
		require.Equal(t, 10*time.Minute, su.MaxAge)
	})

	t.Run("account security, user with a factor: needs a recent second factor", func(t *testing.T) {
		f := newMFAFixture(t)
		secret, _ := f.enrollTOTP(t, aliceID)
		sess := f.passwordSession(t, aliceID) // fresh, but password only

		var su *service.StepUpRequiredError
		require.ErrorAs(t, f.mfa.CheckStepUp(ctx, sess, service.StepUpAccountSecurity), &su)
		require.Equal(t, service.StepUpNeedMFA, su.Reason)

		_, _, err := f.mfa.StepUp(ctx, sess, "totp", "000000", "", "")
		require.ErrorIs(t, err, service.ErrInvalidMFACode)

		upd, method, err := f.mfa.StepUp(ctx, sess, "totp", totpAt(t, secret, f.now), "", "")
		require.NoError(t, err)
		require.Equal(t, domain.MfaMethodTOTP, method)
		require.Equal(t, sess.ID, upd.ID, "same session, upgraded in place")
		require.NoError(t, f.mfa.CheckStepUp(ctx, upd, service.StepUpAccountSecurity))

		f.advance(11 * time.Minute)
		require.ErrorAs(t, f.mfa.CheckStepUp(ctx, upd, service.StepUpAccountSecurity), &su, "verification too old")
	})

	t.Run("sensitive action: role step-up flag demands MFA even without any factor", func(t *testing.T) {
		f := newMFAFixture(t)
		f.access.users[bobID] = activeUser(bobID, []domain.AccessSource{namedRole(roleAdminID, "admin")}, nil)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin", StepUpForSensitiveActions: true})
		require.NoError(t, err)
		sess := f.passwordSession(t, bobID)

		var su *service.StepUpRequiredError
		require.ErrorAs(t, f.mfa.CheckStepUp(ctx, sess, service.StepUpSensitiveAction), &su)
		require.Equal(t, service.StepUpNeedEnrollment, su.Reason)

		require.NoError(t, f.mfa.CheckStepUp(ctx, sess, service.StepUpAccountSecurity),
			"but enrolling a first factor stays possible")
	})

	t.Run("sensitive action: method restricted by the role", func(t *testing.T) {
		f := newMFAFixture(t)
		f.access.users[aliceID] = activeUser(aliceID, []domain.AccessSource{namedRole(roleAdminID, "admin")}, nil)
		_, codes := f.enrollTOTP(t, aliceID)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin",
			AllowedMethods: []domain.MfaMethodType{domain.MfaMethodTOTP}})
		require.NoError(t, err)

		sess := f.passwordSession(t, aliceID)
		upd, _, err := f.mfa.StepUp(ctx, sess, "backup_code", codes[0], "", "")
		require.NoError(t, err)
		var su *service.StepUpRequiredError
		require.ErrorAs(t, f.mfa.CheckStepUp(ctx, upd, service.StepUpSensitiveAction), &su,
			"a backup code does not satisfy a TOTP-only role")
		require.Equal(t, []domain.MfaMethodType{domain.MfaMethodTOTP}, su.AllowedMethods)
	})
}

func TestMFA_IdentityCoreEnforcesClientPolicy(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)
	secret, _ := f.enrollTOTP(t, aliceID)
	sess := f.passwordSession(t, aliceID)

	_, err := f.core.IssueIdentityAssertion(ctx, sess.ID, mfaClientPlain, nil)
	require.NoError(t, err, "a client without requirement accepts a password-only session")

	_, err = f.core.IssueIdentityAssertion(ctx, sess.ID, mfaClientStrict, nil)
	var mfaErr *core.MFARequiredError
	require.ErrorAs(t, err, &mfaErr)
	require.ErrorIs(t, err, core.ErrMFARequired)
	require.False(t, mfaErr.EnrollmentRequired)

	_, _, err = f.mfa.StepUp(ctx, sess, "totp", totpAt(t, secret, f.now), "", "")
	require.NoError(t, err)
	a, err := f.core.IssueIdentityAssertion(ctx, sess.ID, mfaClientStrict, nil)
	require.NoError(t, err)
	require.True(t, a.MFAVerified)
	require.Equal(t, []string{"pwd", "otp", "mfa"}, a.AuthMethods, "RFC 8176 amr")

	_, err = f.core.IssueIdentityAssertion(ctx, sess.ID, mfaClientPasskey, nil)
	require.ErrorAs(t, err, &mfaErr)
	require.True(t, mfaErr.EnrollmentRequired, "passkey-only client, alice has no passkey")
	require.Equal(t, []domain.MfaMethodType{domain.MfaMethodPasskey}, mfaErr.AllowedMethods)

	ok, err := f.core.VerifyMFA(ctx, aliceID, core.MFAChallenge{Method: "totp", Response: "000000"})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestMFA_FactorManagement(t *testing.T) {
	ctx := context.Background()

	t.Run("removing the last factor removes the backup codes too", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		list, err := f.mfa.ListFactors(ctx, aliceID)
		require.NoError(t, err)
		require.Equal(t, 10, list.BackupCodes.Remaining)

		require.ErrorIs(t, f.mfa.DeleteFactor(ctx, f.user(bobID), list.Methods[0].ID), service.ErrMFAMethodNotFound)
		require.NoError(t, f.mfa.DeleteFactor(ctx, f.user(aliceID), list.Methods[0].ID))

		list, err = f.mfa.ListFactors(ctx, aliceID)
		require.NoError(t, err)
		require.Empty(t, list.Methods)
		require.Zero(t, list.BackupCodes.Total)
		require.Equal(t, service.LoginAuthenticated, f.beginLogin(t, aliceID, "").Outcome)
	})

	t.Run("a policy protects the last allowed factor", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		f.settings.set(realmA, func(s *domain.InstanceSettings) { s.MFARequiredGlobally = true })
		list, _ := f.mfa.ListFactors(ctx, aliceID)
		require.ErrorIs(t, f.mfa.DeleteFactor(ctx, f.user(aliceID), list.Methods[0].ID), service.ErrMFARequiredByPolicy)
	})

	t.Run("regenerating backup codes invalidates the old batch", func(t *testing.T) {
		f := newMFAFixture(t)
		_, err := f.mfa.RegenerateBackupCodes(ctx, f.user(bobID))
		require.ErrorIs(t, err, service.ErrNoMFAFactor, "no backup codes without a real factor")

		_, old := f.enrollTOTP(t, aliceID)
		fresh, err := f.mfa.RegenerateBackupCodes(ctx, f.user(aliceID))
		require.NoError(t, err)
		require.Len(t, fresh, 10)

		dec := f.beginLogin(t, aliceID, "")
		_, err = f.verify(dec, "backup_code", old[0])
		require.ErrorIs(t, err, service.ErrInvalidMFACode)
		_, err = f.verify(dec, "backup_code", fresh[0])
		require.NoError(t, err)
	})

	t.Run("a backup code used by two requests at once works only once", func(t *testing.T) {
		f := newMFAFixture(t)
		_, codes := f.enrollTOTP(t, aliceID)
		sess := f.passwordSession(t, aliceID)

		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := f.mfa.StepUp(ctx, sess, "backup_code", codes[1], "", ""); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		require.Equal(t, 1, ok)
	})

	t.Run("admin reset removes everything and revokes the sessions", func(t *testing.T) {
		f := newMFAFixture(t)
		f.enrollTOTP(t, aliceID)
		sess := f.passwordSession(t, aliceID)

		res, err := f.mfa.ResetUser(ctx, f.user(aliceID), "cli:root", "lost phone")
		require.NoError(t, err)
		require.Equal(t, 1, res.MethodsDeleted)
		require.Equal(t, 10, res.BackupCodesDeleted)

		got, err := f.sessions.GetByID(ctx, sess.ID)
		require.NoError(t, err)
		require.Equal(t, domain.SessionRevoked, got.Status)
		require.Equal(t, domain.SessionRevokedMFAReset, got.RevokedReason)
		last := f.audit.entries[len(f.audit.entries)-1]
		require.Equal(t, "mfa_reset", last.Action)
		require.Equal(t, "lost phone", last.Details["reason"])
	})
}

func TestMFA_Notifications(t *testing.T) {
	ctx := context.Background()
	f := newMFAFixture(t)

	f.enrollTOTP(t, aliceID)
	e := f.notifier.last()
	require.Equal(t, domain.NotificationMfaMethodAdded, e.Kind)
	require.Equal(t, domain.MfaMethodTOTP, e.MfaMethodType)
	require.Equal(t, "phone", e.MfaMethodName)
	require.Equal(t, aliceID, e.UserID)
	require.Equal(t, realmA, e.RealmID)

	_, err := f.mfa.RegenerateBackupCodes(ctx, f.user(aliceID))
	require.NoError(t, err)
	require.Equal(t, domain.NotificationBackupCodesRegenerated, f.notifier.last().Kind)

	list, err := f.mfa.ListFactors(ctx, aliceID)
	require.NoError(t, err)
	require.NoError(t, f.mfa.DeleteFactor(ctx, f.user(aliceID), list.Methods[0].ID))
	require.Equal(t, domain.NotificationMfaMethodRemoved, f.notifier.last().Kind)

	f.enrollTOTP(t, aliceID)
	_, err = f.mfa.ResetUser(ctx, f.user(aliceID), "cli:root", "lost phone")
	require.NoError(t, err)
	require.Equal(t, []domain.NotificationKind{
		domain.NotificationMfaMethodAdded,
		domain.NotificationBackupCodesRegenerated,
		domain.NotificationMfaMethodRemoved,
		domain.NotificationMfaMethodAdded,
		domain.NotificationMfaReset,
	}, f.notifier.kinds())

	// A pending (never confirmed) factor is not worth an e-mail.
	enr, err := f.mfa.StartTOTPEnrollment(ctx, f.user(bobID), "tablet")
	require.NoError(t, err)
	require.NoError(t, f.mfa.DeleteFactor(ctx, f.user(bobID), enr.MethodID))
	require.Len(t, f.notifier.kinds(), 5)
}

func TestMFA_DeviceFingerprintKept(t *testing.T) {
	f := newMFAFixture(t)
	secret, _ := f.enrollTOTP(t, aliceID)
	dec, err := f.mfa.BeginLogin(context.Background(), service.BeginLoginInput{
		User: f.user(aliceID), IPAddress: "203.0.113.9", DeviceFingerprint: "device-hash",
	})
	require.NoError(t, err)
	require.Equal(t, service.LoginMFARequired, dec.Outcome)
	res, err := f.verify(dec, "totp", totpAt(t, secret, f.now))
	require.NoError(t, err)
	require.Equal(t, "device-hash", f.sessions.byID[res.Session.ID].DeviceFingerprint)
}

func TestMFA_RateLimit(t *testing.T) {
	f := newMFAFixture(t)
	secret, _ := f.enrollTOTP(t, aliceID)
	f.limiter.limit = 2
	f.limiter.seen = map[string]int64{}

	sess := f.passwordSession(t, aliceID)
	for i := 0; i < 2; i++ {
		_, _, err := f.mfa.StepUp(context.Background(), sess, "totp", "000000", "", "")
		require.ErrorIs(t, err, service.ErrInvalidMFACode)
	}
	_, _, err := f.mfa.StepUp(context.Background(), sess, "totp", totpAt(t, secret, f.now), "", "")
	require.ErrorIs(t, err, service.ErrMFARateLimited, "even a correct code once the limit is reached")
}

func TestMFAPolicyService(t *testing.T) {
	ctx := context.Background()

	t.Run("role policy keeps its grace start across edits", func(t *testing.T) {
		f := newMFAFixture(t)
		p, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin", Required: true, EnrollmentGraceDays: 3})
		require.NoError(t, err)
		start := p.RequiredSince
		require.Equal(t, f.now, start)

		f.advance(time.Hour)
		p, err = f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin", Required: true, EnrollmentGraceDays: 5})
		require.NoError(t, err)
		require.Equal(t, start, p.RequiredSince, "changing the grace length does not restart it")

		p, err = f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin"})
		require.NoError(t, err)
		require.True(t, p.RequiredSince.IsZero())
		require.Equal(t, "mfa_policy_changed", f.audit.entries[len(f.audit.entries)-1].Action)
	})

	t.Run("validation", func(t *testing.T) {
		f := newMFAFixture(t)
		_, err := f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "nope"})
		require.ErrorIs(t, err, repository.ErrNotFound)
		_, err = f.policy.SetRolePolicy(ctx, service.SetRoleMFAPolicyInput{RealmID: realmA, RoleName: "admin", AllowedMethods: []domain.MfaMethodType{"sms"}})
		require.ErrorIs(t, err, service.ErrUnknownMFAMethod)
		_, err = f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: realmA, ClientRef: mfaClientPlain, Policy: "sometimes"})
		require.ErrorIs(t, err, service.ErrUnknownMFAPolicy)
		_, err = f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: "other-realm", ClientRef: mfaClientPlain, Policy: domain.ClientAppMFARequired})
		require.ErrorIs(t, err, repository.ErrNotFound, "a client of another realm")
		d := 30 * time.Second
		_, err = f.policy.SetRealmPolicy(ctx, service.SetRealmMFAPolicyInput{RealmID: realmA, StepUpMaxAge: &d})
		require.ErrorIs(t, err, service.ErrInvalidMFAPolicy)

		_, err = service.ParseMFAMethods("totp, PASSKEY,backup_code")
		require.NoError(t, err)
		_, err = service.ParseMFAMethods("totp,sms")
		require.ErrorIs(t, err, service.ErrUnknownMFAMethod)
		m, err := service.ParseMFAMethods("any")
		require.NoError(t, err)
		require.Nil(t, m)
	})

	t.Run("client policy round trip", func(t *testing.T) {
		f := newMFAFixture(t)
		c, err := f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{
			RealmID: realmA, ClientRef: mfaClientPlain, Policy: domain.ClientAppMFARequired,
			AllowedMethods: []domain.MfaMethodType{domain.MfaMethodTOTP},
		})
		require.NoError(t, err)
		require.Equal(t, domain.ClientAppMFARequired, c.MFAPolicy)
		require.Equal(t, service.LoginMFAEnrollmentRequired, f.beginLogin(t, bobID, mfaClientPlain).Outcome)

		c, err = f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: realmA, ClientRef: mfaClientPlain, Policy: domain.ClientAppMFAInherit})
		require.NoError(t, err)
		require.Nil(t, c.MFAAllowedMethods, "methods cleared")
	})

	t.Run("resources managed by the config file are read-only here", func(t *testing.T) {
		f := newMFAFixture(t)
		f.clients.byID[mfaClientPlain].ManagedBy = domain.ClientAppManagedByConfig
		_, err := f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: realmA, ClientRef: mfaClientPlain, Policy: domain.ClientAppMFARequired})
		require.ErrorIs(t, err, service.ErrManagedByConfig)
		_, err = f.policy.SetClientPolicy(ctx, service.SetClientMFAPolicyInput{RealmID: realmA, ClientRef: mfaClientPlain, Policy: domain.ClientAppMFARequired,
			Actor: service.PolicyActor{FromConfig: true}})
		require.NoError(t, err, "the reconciler may")
	})

	t.Run("realm policy creates the settings row when missing", func(t *testing.T) {
		f := newMFAFixture(t)
		yes, d := true, 5*time.Minute
		s, err := f.policy.SetRealmPolicy(ctx, service.SetRealmMFAPolicyInput{RealmID: realmA, RequiredGlobally: &yes, StepUpMaxAge: &d})
		require.NoError(t, err)
		require.True(t, s.MFARequiredGlobally)
		require.Equal(t, 5, s.MFAStepUpMaxAgeMinutes)
		require.Equal(t, 5*time.Minute, f.policy.StepUpMaxAge(ctx, realmA))
	})
}

func TestEnvelope(t *testing.T) {
	ctx := context.Background()
	keys := memstore.NewSigningKeys(nil)
	km := localdev.New("test")
	env := service.NewEnvelopeService(keys, km, "local_dev")
	aad := []byte("user:alice")

	sealed, err := env.Seal(ctx, realmA, []byte("JBSWY3DPEHPK3PXP"), aad)
	require.NoError(t, err)
	require.NotContains(t, sealed, "JBSWY3DPEHPK3PXP")

	plain, err := env.Open(ctx, sealed, aad)
	require.NoError(t, err)
	require.Equal(t, "JBSWY3DPEHPK3PXP", string(plain))

	again, err := env.Seal(ctx, realmA, []byte("JBSWY3DPEHPK3PXP"), aad)
	require.NoError(t, err)
	require.NotEqual(t, sealed, again, "fresh data key and nonce every time")

	all, err := keys.ListByRealm(ctx, realmA)
	require.NoError(t, err)
	require.Len(t, all, 1, "one KEK per realm, created on first use and reused")
	require.Equal(t, domain.SigningKeyPurposeEnvelopeEncrypt, all[0].Purpose)
	require.Equal(t, domain.SigningKeyAES, all[0].KeyType)
	require.Empty(t, all[0].PublicKey)

	_, err = env.Open(ctx, sealed, []byte("user:bob"))
	require.ErrorIs(t, err, service.ErrEnvelopeCorrupted, "secret moved to another user: does not decrypt")

	tampered := strings.Replace(sealed, `"ct":"`, `"ct":"AAAA`, 1)
	_, err = env.Open(ctx, tampered, aad)
	require.ErrorIs(t, err, service.ErrEnvelopeCorrupted)

	_, err = env.Open(ctx, "not json", aad)
	require.ErrorIs(t, err, service.ErrEnvelopeCorrupted)

	other := service.NewEnvelopeService(keys, km, "vault")
	_, err = other.Open(ctx, sealed, aad)
	require.ErrorIs(t, err, service.ErrEnvelopeBackendMismatch)

	var none *service.EnvelopeService
	_, err = none.Seal(ctx, realmA, []byte("x"), nil)
	require.ErrorIs(t, err, service.ErrEnvelopeNotConfigured)

	t.Run("survives a restart only with the same master key", func(t *testing.T) {
		master := []byte(strings.Repeat("k", 32))
		keys := memstore.NewSigningKeys(nil)
		first := service.NewEnvelopeService(keys, localdev.New("test", localdev.WithEnvelopeMasterKey(master)), "local_dev")
		sealed, err := first.Seal(ctx, realmA, []byte("secret"), nil)
		require.NoError(t, err)

		restarted := service.NewEnvelopeService(keys, localdev.New("test", localdev.WithEnvelopeMasterKey(master)), "local_dev")
		plain, err := restarted.Open(ctx, sealed, nil)
		require.NoError(t, err)
		require.Equal(t, "secret", string(plain))

		lost := service.NewEnvelopeService(keys, localdev.New("test"), "local_dev")
		_, err = lost.Open(ctx, sealed, nil)
		require.Error(t, err)
	})
}

// Make sure the error type helpers behave as documented.
func TestMFA_ErrorTypes(t *testing.T) {
	var err error = &service.MFACodeError{AttemptsRemaining: 2}
	require.ErrorIs(t, err, service.ErrInvalidMFACode)
	err = fmt.Errorf("wrapped: %w", &service.StepUpRequiredError{Reason: service.StepUpNeedMFA})
	require.ErrorIs(t, err, service.ErrStepUpRequired)
	require.True(t, errors.Is(&core.MFARequiredError{}, core.ErrMFARequired))
}
