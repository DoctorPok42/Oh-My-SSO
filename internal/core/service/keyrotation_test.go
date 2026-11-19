package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/core/service"
	localdev "sso.internal/sso/internal/keymanager/local_dev"
	"sso.internal/sso/internal/storage/memstore"
)


const (
	rotRealm      = "realm-rot"
	rotOtherRealm = "realm-rot-other"
	rotBy         = "test:rotation"
)

// rotSettings returns a fixed InstanceSettings (or an error).
type rotSettings struct {
	repository.InstanceSettingsRepository
	graceHours   int
	intervalDays int
	err          error
	claimedUntil time.Time // ClaimKeyRotation: held until then
	created      int       // calls to Create
}

func (f *rotSettings) GetByRealmID(_ context.Context, realmID string) (*domain.InstanceSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.graceHours == 0 && f.intervalDays == 0 {
		return nil, repository.ErrNotFound
	}
	return &domain.InstanceSettings{RealmID: realmID, KeyRotationGraceHours: f.graceHours, KeyRotationIntervalDays: f.intervalDays}, nil
}

// Create gives the realm the column defaults (90 days), like the real table.
func (f *rotSettings) Create(context.Context, repository.CreateInstanceSettingsParams) (*domain.InstanceSettings, error) {
	f.intervalDays, f.created = 90, f.created+1
	return &domain.InstanceSettings{KeyRotationIntervalDays: 90}, nil
}

func (f *rotSettings) ClaimKeyRotation(_ context.Context, _ string, now, until time.Time) (bool, error) {
	if now.Before(f.claimedUntil) {
		return false, nil
	}
	f.claimedUntil = until
	return true, nil
}

// failingLogs fails every write: used to check partial failures.
type failingLogs struct {
	repository.KeyRotationLogRepository
}

func (failingLogs) Create(context.Context, repository.CreateKeyRotationLogParams) (*domain.KeyRotationLog, error) {
	return nil, errors.New("log table unavailable")
}

type rotFixture struct {
	now      time.Time
	keys     *memstore.SigningKeys
	logs     *memstore.KeyRotationLogs
	settings *rotSettings
	km       *localdev.KeyManager
	rot      *service.KeyRotationService
	core     *service.IdentityCoreService
}

func newRotFixture(t *testing.T) *rotFixture { return newRotFixtureOn(t, "local_dev") }

// newRotFixtureOn names the backend stored on the keys. The key manager is
// always the in-process local_dev one; RotateDue refuses the name "local_dev"
// (its keys would not be shared between servers), so its tests use another.
func newRotFixtureOn(t *testing.T, backend string) *rotFixture {
	t.Helper()
	f := &rotFixture{now: time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }
	f.keys = memstore.NewSigningKeys(clock)
	f.logs = memstore.NewKeyRotationLogs(clock)
	f.settings = &rotSettings{}
	f.km = localdev.New("test")
	f.rot = service.NewKeyRotationService(f.keys, f.logs, f.settings, f.km, backend,
		service.WithKeyRotationClock(clock))
	// Signer and PublicKeys only need the keys and the KeyManager.
	f.core = service.NewIdentityCore(service.IdentityCoreDeps{SigningKeys: f.keys, KeyManager: f.km},
		service.WithIdentityCoreClock(clock))
	return f
}

func (f *rotFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *rotFixture) rotate(t *testing.T, in service.RotateInput) *service.RotateResult {
	t.Helper()
	if in.RealmID == "" {
		in.RealmID = rotRealm
	}
	if in.TriggeredBy == "" {
		in.TriggeredBy = rotBy
	}
	res, err := f.rot.Rotate(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res.NewKey)
	f.advance(time.Second) // two keys never share a CreatedAt
	return res
}

func (f *rotFixture) key(t *testing.T, kid string) *domain.SigningKey {
	t.Helper()
	k, err := f.keys.GetByKid(context.Background(), kid)
	require.NoError(t, err)
	return k
}

func (f *rotFixture) publishedKids(t *testing.T) []string {
	t.Helper()
	keys, err := f.core.PublicKeys(context.Background(), rotRealm, domain.SigningKeyPurposeJWT)
	require.NoError(t, err)
	kids := make([]string, 0, len(keys))
	for _, k := range keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func (f *rotFixture) signerKid(t *testing.T) string {
	t.Helper()
	s, err := f.core.Signer(context.Background(), rotRealm, domain.SigningKeyPurposeJWT)
	require.NoError(t, err)
	return s.KeyID()
}

func actions(logs []*domain.KeyRotationLog) []domain.KeyRotationAction {
	out := make([]domain.KeyRotationAction, 0, len(logs))
	for _, l := range logs {
		out = append(out, l.Action)
	}
	return out
}

func TestRotate_FirstKeyOfARealm(t *testing.T) {
	f := newRotFixture(t)

	res := f.rotate(t, service.RotateInput{Reason: "bootstrap"})

	require.Equal(t, domain.SigningKeyRSA, res.NewKey.KeyType, "RSA by default: RS256 is mandatory in OIDC")
	require.Equal(t, domain.SigningKeyActive, res.NewKey.Status)
	require.Equal(t, domain.SigningKeyPurposeJWT, res.NewKey.Purpose)
	require.Equal(t, "local_dev", res.NewKey.KMSBackend)
	require.NotEmpty(t, res.NewKey.PublicKey)
	require.Empty(t, res.Rotating)
	require.Equal(t, service.DefaultKeyRotationGrace, res.Grace)

	require.Equal(t, res.NewKey.Kid, f.signerKid(t))
	require.Equal(t, []string{res.NewKey.Kid}, f.publishedKids(t))

	logs := f.logs.All()
	require.Equal(t, []domain.KeyRotationAction{domain.KeyRotationCreated}, actions(logs))
	require.Equal(t, rotBy, logs[0].TriggeredBy)
	require.Equal(t, "bootstrap", logs[0].Reason)
}

func TestRotate_OldKeyEntersGracePeriod(t *testing.T) {
	f := newRotFixture(t)
	f.settings.graceHours = 48 // realm setting

	first := f.rotate(t, service.RotateInput{}).NewKey
	rotatedAt := f.now
	second := f.rotate(t, service.RotateInput{}).NewKey

	old := f.key(t, first.Kid)
	require.Equal(t, domain.SigningKeyRotating, old.Status)
	require.Equal(t, rotatedAt.Add(48*time.Hour), old.RetireAfter, "deadline = rotation time + realm grace")

	require.Equal(t, second.Kid, f.signerKid(t), "only the new key signs")
	require.Equal(t, []string{second.Kid, first.Kid}, f.publishedKids(t), "both published, newest first")

	logs, err := f.logs.ListBySigningKey(context.Background(), first.ID)
	require.NoError(t, err)
	require.Equal(t, domain.KeyRotationRotated, logs[0].Action)
	require.Contains(t, logs[0].Reason, "superseded by kid "+second.Kid)
}

func TestRotate_GracePeriodSources(t *testing.T) {
	ctx := context.Background()

	t.Run("no settings row: 24h default", func(t *testing.T) {
		f := newRotFixture(t)
		g, err := f.rot.GracePeriod(ctx, rotRealm)
		require.NoError(t, err)
		require.Equal(t, 24*time.Hour, g)
	})

	t.Run("explicit override wins over the realm setting", func(t *testing.T) {
		f := newRotFixture(t)
		f.settings.graceHours = 48
		f.rotate(t, service.RotateInput{})
		res := f.rotate(t, service.RotateInput{Grace: 3 * time.Hour})
		require.Equal(t, 3*time.Hour, res.Grace)
	})

	t.Run("too short is refused before anything is created", func(t *testing.T) {
		f := newRotFixture(t)
		_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, Grace: 30 * time.Minute})
		require.ErrorIs(t, err, service.ErrGraceTooShort)
		keys, _ := f.keys.ListByRealm(ctx, rotRealm)
		require.Empty(t, keys)
	})

	t.Run("settings read error is not silently ignored", func(t *testing.T) {
		f := newRotFixture(t)
		f.settings.err = errors.New("db down")
		_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy})
		require.Error(t, err)
		keys, _ := f.keys.ListByRealm(ctx, rotRealm)
		require.Empty(t, keys)
	})
}

func TestRotate_KeyType(t *testing.T) {
	f := newRotFixture(t)

	ec := f.rotate(t, service.RotateInput{KeyType: domain.SigningKeyEC}).NewKey
	require.Equal(t, domain.SigningKeyEC, ec.KeyType)

	same := f.rotate(t, service.RotateInput{}).NewKey
	require.Equal(t, domain.SigningKeyEC, same.KeyType, "empty KeyType keeps the current type")

	back := f.rotate(t, service.RotateInput{KeyType: domain.SigningKeyRSA}).NewKey
	require.Equal(t, domain.SigningKeyRSA, back.KeyType)

	_, err := f.rot.Rotate(context.Background(), service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, KeyType: "HS256"})
	require.Error(t, err)
}

func TestRotate_RotatingKeyKeepsItsOriginalDeadline(t *testing.T) {
	f := newRotFixture(t)
	k1 := f.rotate(t, service.RotateInput{}).NewKey
	f.rotate(t, service.RotateInput{}) // k1 -> rotating
	deadline := f.key(t, k1.Kid).RetireAfter

	f.advance(time.Hour)
	f.rotate(t, service.RotateInput{}) // must not push k1's deadline back

	require.Equal(t, deadline, f.key(t, k1.Kid).RetireAfter)
}

func TestRetireExpired(t *testing.T) {
	ctx := context.Background()
	f := newRotFixture(t)
	k1 := f.rotate(t, service.RotateInput{}).NewKey
	k2 := f.rotate(t, service.RotateInput{}).NewKey // k1 rotating until now+24h

	f.advance(23 * time.Hour)
	retired, err := f.rot.RetireExpired(ctx, rotRealm, rotBy)
	require.NoError(t, err)
	require.Empty(t, retired, "still inside the grace period")
	require.Equal(t, []string{k2.Kid, k1.Kid}, f.publishedKids(t))

	f.advance(2 * time.Hour)
	// Even BEFORE the retire job runs, the expired key is no longer published.
	require.Equal(t, []string{k2.Kid}, f.publishedKids(t))

	retired, err = f.rot.RetireExpired(ctx, rotRealm, rotBy)
	require.NoError(t, err)
	require.Len(t, retired, 1)
	require.Equal(t, k1.Kid, retired[0].Kid)

	got := f.key(t, k1.Kid)
	require.Equal(t, domain.SigningKeyRetired, got.Status)
	require.Equal(t, f.now, got.RetiredAt)

	logs, _ := f.logs.ListBySigningKey(ctx, k1.ID)
	require.Equal(t, domain.KeyRotationRetired, logs[0].Action)
	require.Equal(t, rotBy, logs[0].TriggeredBy)

	// Idempotent.
	retired, err = f.rot.RetireExpired(ctx, rotRealm, rotBy)
	require.NoError(t, err)
	require.Empty(t, retired)
}

func TestRotate_AlsoRetiresExpiredKeys(t *testing.T) {
	f := newRotFixture(t)
	k1 := f.rotate(t, service.RotateInput{}).NewKey
	f.rotate(t, service.RotateInput{})
	f.advance(25 * time.Hour)

	res := f.rotate(t, service.RotateInput{})

	require.Len(t, res.Retired, 1)
	require.Equal(t, k1.Kid, res.Retired[0].Kid)
}

func TestRotate_Compromised(t *testing.T) {
	ctx := context.Background()
	f := newRotFixture(t)
	k1 := f.rotate(t, service.RotateInput{}).NewKey
	k2 := f.rotate(t, service.RotateInput{}).NewKey // k1 rotating, k2 active

	_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, Compromised: true})
	require.ErrorIs(t, err, service.ErrCompromisedReasonRequired)

	res := f.rotate(t, service.RotateInput{Compromised: true, Reason: "private key leaked"})

	require.Zero(t, res.Grace)
	require.Empty(t, res.Rotating)
	require.ElementsMatch(t, []string{k1.Kid, k2.Kid}, []string{res.Retired[0].Kid, res.Retired[1].Kid},
		"active AND rotating keys are retired at once")
	require.Equal(t, []string{res.NewKey.Kid}, f.publishedKids(t), "only the fresh key is published")

	for _, k := range []*domain.SigningKey{k1, k2} {
		logs, _ := f.logs.ListBySigningKey(ctx, k.ID)
		require.Equal(t, domain.KeyRotationCompromised, logs[0].Action)
		require.Equal(t, "private key leaked", logs[0].Reason)
	}
}

func TestRotate_RefusedInputs(t *testing.T) {
	ctx := context.Background()
	f := newRotFixture(t)

	for _, purpose := range []domain.SigningKeyPurpose{
		domain.SigningKeyPurposeEnvelopeEncrypt, // would make encrypted secrets unreadable
		domain.SigningKeyPurposeSAMLEncryption,
	} {
		_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy, Purpose: purpose})
		require.ErrorIs(t, err, service.ErrUnsupportedRotationPurpose, purpose)
	}

	_, err := f.rot.Rotate(ctx, service.RotateInput{RealmID: rotRealm})
	require.ErrorIs(t, err, service.ErrRotationTriggeredByRequired)

	_, err = f.rot.Rotate(ctx, service.RotateInput{TriggeredBy: rotBy})
	require.Error(t, err)
}

func TestRotate_OnlyTouchesItsRealmAndPurpose(t *testing.T) {
	f := newRotFixture(t)
	other := f.rotate(t, service.RotateInput{RealmID: rotOtherRealm}).NewKey
	saml := &domain.SigningKey{ID: "saml", RealmID: rotRealm, Kid: "saml-kid", KeyType: domain.SigningKeyRSA,
		Purpose: domain.SigningKeyPurposeSAMLSigning, Status: domain.SigningKeyActive, CreatedAt: f.now.Add(-time.Hour)}
	f.keys.Add(saml)

	f.rotate(t, service.RotateInput{})
	f.rotate(t, service.RotateInput{})

	require.Equal(t, domain.SigningKeyActive, f.key(t, other.Kid).Status, "other realm untouched")
	require.Equal(t, domain.SigningKeyActive, f.key(t, "saml-kid").Status, "other purpose untouched")
	require.NotContains(t, f.publishedKids(t), "saml-kid", "SAML keys are not in the JWKS")
	require.NotContains(t, f.publishedKids(t), other.Kid, "other realm's keys are not in the JWKS")
}

func TestRotate_ConcurrentRotationsNewestWins(t *testing.T) {
	f := newRotFixture(t)
	k0 := f.rotate(t, service.RotateInput{}).NewKey

	// Rotation B already created its key a bit "in the future" of rotation A
	// (both run at the same time; B's key happens to be the most recent).
	gen, err := f.km.GenerateKey(context.Background(), "rsa", 0)
	require.NoError(t, err)
	f.keys.Add(&domain.SigningKey{ID: "kb", RealmID: rotRealm, Kid: "kid-b", KeyType: domain.SigningKeyRSA,
		Purpose: domain.SigningKeyPurposeJWT, Status: domain.SigningKeyActive, KMSKeyReference: gen.KMSKeyReference,
		PublicKey: gen.PublicKeyPEM, CreatedAt: f.now.Add(time.Minute)})

	// Rotation A: creates kA (older than kB), must demote k0 but NOT kB.
	a := f.rotate(t, service.RotateInput{}).NewKey

	require.Equal(t, domain.SigningKeyRotating, f.key(t, k0.Kid).Status)
	require.Equal(t, domain.SigningKeyActive, f.key(t, "kid-b").Status)
	require.Equal(t, domain.SigningKeyActive, f.key(t, a.Kid).Status, "demoted later by B, never left without active key")
	require.Equal(t, "kid-b", f.signerKid(t), "the newest active key signs")
}

func TestRotate_PartialFailureKeepsTheNewKey(t *testing.T) {
	f := newRotFixture(t)
	k1 := f.rotate(t, service.RotateInput{}).NewKey

	clock := func() time.Time { return f.now }
	broken := service.NewKeyRotationService(f.keys, failingLogs{}, f.settings, f.km, "local_dev",
		service.WithKeyRotationClock(clock))
	res, err := broken.Rotate(context.Background(), service.RotateInput{RealmID: rotRealm, TriggeredBy: rotBy})

	require.Error(t, err, "the log failures are reported")
	require.NotNil(t, res)
	require.NotNil(t, res.NewKey, "but the new key exists")
	require.Equal(t, res.NewKey.Kid, f.signerKid(t), "and signs")
	require.Equal(t, domain.SigningKeyRotating, f.key(t, k1.Kid).Status, "and the old one was still demoted")
}

func TestVerificationKeys(t *testing.T) {
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	mk := func(kid string, status domain.SigningKeyStatus, purpose domain.SigningKeyPurpose, created, retireAfter time.Time) *domain.SigningKey {
		return &domain.SigningKey{Kid: kid, Status: status, Purpose: purpose, CreatedAt: created, RetireAfter: retireAfter}
	}
	jwt := domain.SigningKeyPurposeJWT
	keys := []*domain.SigningKey{
		mk("old-active", domain.SigningKeyActive, jwt, now.Add(-3*time.Hour), time.Time{}),
		mk("new-active", domain.SigningKeyActive, jwt, now.Add(-time.Hour), time.Time{}),
		mk("in-grace", domain.SigningKeyRotating, jwt, now.Add(-2*time.Hour), now.Add(time.Minute)),
		mk("grace-over", domain.SigningKeyRotating, jwt, now.Add(-4*time.Hour), now),
		mk("legacy-rotating", domain.SigningKeyRotating, jwt, now.Add(-5*time.Hour), time.Time{}),
		mk("retired", domain.SigningKeyRetired, jwt, now.Add(-6*time.Hour), time.Time{}),
		mk("saml", domain.SigningKeyActive, domain.SigningKeyPurposeSAMLSigning, now, time.Time{}),
	}

	got := service.VerificationKeys(keys, jwt, now)

	kids := make([]string, 0, len(got))
	for _, k := range got {
		kids = append(kids, k.Kid)
	}
	require.Equal(t, []string{"new-active", "in-grace", "old-active", "legacy-rotating"}, kids)
}

func TestRotateDue(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour

	t.Run("a key older than the interval is rotated, as the system", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault")
		f.settings.intervalDays = 90
		first := f.rotate(t, service.RotateInput{}).NewKey
		f.advance(91 * day)

		rotated, err := f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.True(t, rotated)

		require.NotEqual(t, first.Kid, f.signerKid(t), "a new key signs")
		require.Equal(t, domain.SigningKeyRotating, f.key(t, first.Kid).Status, "the old one enters its grace period")
		logs := f.logs.All()
		created := logs[len(logs)-2] // then "rotated" for the old key
		require.Equal(t, domain.KeyRotationCreated, created.Action)
		require.Equal(t, "system", created.TriggeredBy)
		require.Contains(t, created.Reason, "90 days")
	})

	// Same setup (a first key, then time passes), one reason not to rotate each.
	for _, c := range []struct {
		name     string
		backend  string
		interval int  // key_rotation_interval_days
		grace    int  // a settings row exists even with interval 0
		days     int  // age of the key
		claimed  bool // another instance holds the claim
	}{
		{name: "a younger key is left alone", backend: "vault", interval: 90, days: 89},
		{name: "0 turns it off", backend: "vault", grace: 24, days: 1000},
		{name: "local_dev keys are never rotated by itself", backend: "local_dev", interval: 90, days: 1000},
		{name: "another instance holds the claim: this one does not rotate", backend: "vault", interval: 90, days: 91, claimed: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRotFixtureOn(t, c.backend)
			f.settings.intervalDays, f.settings.graceHours = c.interval, c.grace
			first := f.rotate(t, service.RotateInput{}).NewKey
			f.advance(time.Duration(c.days) * day)
			if c.claimed {
				f.settings.claimedUntil = f.now.Add(time.Minute)
			}

			rotated, err := f.rot.RotateDue(ctx, rotRealm)
			require.NoError(t, err)
			require.False(t, rotated)
			require.Equal(t, first.Kid, f.signerKid(t))
		})
	}

	t.Run("no key: nothing to do (an empty realm gets its first key elsewhere)", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault")
		f.settings.intervalDays = 90
		rotated, err := f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.False(t, rotated)
	})

	t.Run("a realm without a settings row gets one, with the 90-day default", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault")
		first := f.rotate(t, service.RotateInput{}).NewKey // no settings row yet
		require.Zero(t, f.settings.created)
		f.advance(91 * day)

		rotated, err := f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.True(t, rotated)
		require.Equal(t, 1, f.settings.created)
		require.NotEqual(t, first.Kid, f.signerKid(t))
	})

	t.Run("two ticks in a row rotate once", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault")
		f.settings.intervalDays = 90
		f.rotate(t, service.RotateInput{})
		f.advance(91 * day)

		rotated, err := f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.True(t, rotated)
		rotated, err = f.rot.RotateDue(ctx, rotRealm)
		require.NoError(t, err)
		require.False(t, rotated)
	})

	t.Run("a settings read error is returned", func(t *testing.T) {
		f := newRotFixtureOn(t, "vault")
		f.settings.err = errors.New("db down")
		_, err := f.rot.RotateDue(ctx, rotRealm)
		require.ErrorContains(t, err, "db down")
	})
}
