package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/keymanager"
)


const (
	// DefaultKeyRotationGrace is used when the realm has no InstanceSettings
	// (or a non-positive value). 24h covers any token lifetime we plan to
	// use (id_token / access_token: minutes to one hour) with a wide margin.
	DefaultKeyRotationGrace = 24 * time.Hour

	// MinKeyRotationGrace is the shortest grace period accepted for a normal
	// rotation. It must stay above "longest token lifetime + JWKS cache
	// max-age" (1h + 5min today), otherwise a perfectly valid token could
	// fail verification after a routine rotation.
	MinKeyRotationGrace = time.Hour

	keyRotationReasonGraceEnded = "grace period ended"
)

var (
	ErrGraceTooShort               = errors.New("service: key rotation grace period is too short")
	ErrUnsupportedRotationPurpose  = errors.New("service: rotation is not supported for this key purpose")
	ErrRotationTriggeredByRequired = errors.New("service: key rotation needs a triggered_by value")
	ErrCompromisedReasonRequired   = errors.New("service: a compromised-key rotation needs a reason")
	// ErrPendingKeyExists: a staged rotation already waits for Activate.
	ErrPendingKeyExists = errors.New("service: a pending key already exists: activate it first (or rotate with compromised)")
	// ErrNoPendingKey: Activate found no "pending" key to activate.
	ErrNoPendingKey = errors.New("service: no pending key to activate")
	// ErrActivationNotSupported: this purpose rotates in one step, it never
	// has pending keys.
	ErrActivationNotSupported = errors.New("service: this key purpose rotates in one step, there is nothing to activate")
)

var rotatablePurposes = map[domain.SigningKeyPurpose]bool{
	domain.SigningKeyPurposeJWT:         true,
	domain.SigningKeyPurposeSAMLSigning: true,
}

// stagedPurposes rotate in two steps (Rotate creates a "pending" key,
// Activate makes it sign).
var stagedPurposes = map[domain.SigningKeyPurpose]bool{
	domain.SigningKeyPurposeSAMLSigning: true,
}

// KeyRotationService creates, rotates and retires signing keys.
type KeyRotationService struct {
	keys       repository.SigningKeyRepository
	logs       repository.KeyRotationLogRepository
	settings   repository.InstanceSettingsRepository
	km         keymanager.KeyManager
	kmsBackend string // "vault", "local_dev", "ovhkms": stored on each key
	now        func() time.Time
	logger     *slog.Logger
}

type KeyRotationOption func(*KeyRotationService)

// WithKeyRotationClock injects a fake clock (tests).
func WithKeyRotationClock(now func() time.Time) KeyRotationOption {
	return func(s *KeyRotationService) { s.now = now }
}

func WithKeyRotationLogger(l *slog.Logger) KeyRotationOption {
	return func(s *KeyRotationService) { s.logger = l }
}

func NewKeyRotationService(
	keys repository.SigningKeyRepository,
	logs repository.KeyRotationLogRepository,
	settings repository.InstanceSettingsRepository,
	km keymanager.KeyManager,
	kmsBackend string,
	opts ...KeyRotationOption,
) *KeyRotationService {
	s := &KeyRotationService{
		keys:       keys,
		logs:       logs,
		settings:   settings,
		km:         km,
		kmsBackend: kmsBackend,
		now:        time.Now,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RotateInput describes one rotation.
type RotateInput struct {
	RealmID string
	// Purpose defaults to jwt_signing.
	Purpose domain.SigningKeyPurpose
	// KeyType of the new key. Empty means "same type as the current active
	// key", or RSA if there is none (RS256 is the one algorithm every OIDC
	// client must support, OIDC Core §15.1).
	KeyType domain.SigningKeyType
	// Grace overrides the realm's key_rotation_grace_hours when > 0.
	Grace time.Duration
	// Compromised retires every previous key of that purpose immediately,
	// with no grace period: tokens they signed stop verifying right away
	// (users have to log in again). Use it when a private key may have leaked.
	Compromised bool
	// TriggeredBy is written to KeyRotationLog: "user:<id>", "cli:<os user>"...
	TriggeredBy string
	Reason      string
}

// RotateResult tells what happened, for the HTTP response / CLI output.
type RotateResult struct {
	// NewKey is the key created (Rotate) or activated (Activate). After a
	// staged rotation its status is "pending".
	NewKey *domain.SigningKey
	// Rotating are the previous active keys, now in their grace period.
	Rotating []*domain.SigningKey
	// Retired are the keys retired by this call: expired ones found on the
	// way, plus every previous key on a compromised rotation.
	Retired []*domain.SigningKey
	// Grace is the grace period applied to Rotating (0 when compromised).
	Grace time.Duration
}

// Rotate creates a new key, which becomes the one that signs, then moves the
// previous active keys of the same purpose to "rotating" (or straight to
// "retired" when Compromised).
//
// Order matters: the new key is created FIRST. If something fails afterwards,
// the realm has two active keys for a while, which is harmless (Signer picks
// the newest, both are published). The opposite order could leave a realm
// with no active key at all, i.e. unable to issue any token.
//
// Concurrency: only keys created before the new one are demoted. If two
// rotations run at the same time, the most recent key stays active and the
// other one is demoted by the most recent rotation - never both.
func (s *KeyRotationService) Rotate(ctx context.Context, in RotateInput) (*RotateResult, error) {
	if in.Purpose == "" {
		in.Purpose = domain.SigningKeyPurposeJWT
	}
	if err := s.validate(in); err != nil {
		return nil, err
	}

	grace, err := s.gracePeriod(ctx, in)
	if err != nil {
		return nil, err
	}

	res := &RotateResult{Grace: grace}

	// Tidy up first: rotating keys whose grace already ended. Best effort,
	// a failure here must not block an (maybe urgent) rotation.
	expired, err := s.RetireExpired(ctx, in.RealmID, in.TriggeredBy)
	if err != nil {
		s.logger.WarnContext(ctx, "key rotation: could not retire expired keys",
			"realm_id", in.RealmID, "error", err)
	}
	res.Retired = append(res.Retired, expired...)

	current, err := s.keys.ListActiveByRealm(ctx, in.RealmID)
	if err != nil {
		return nil, fmt.Errorf("key rotation: list keys: %w", err)
	}
	current = filterPurpose(current, in.Purpose)

	keyType := in.KeyType
	if keyType == "" {
		keyType = domain.SigningKeyRSA
		if newest := newestWithStatus(current, domain.SigningKeyActive); newest != nil {
			keyType = newest.KeyType
		}
	}

	// Two-step purposes (SAML): the new key only signs after Activate, unless
	// there is no key to replace yet or the old one is compromised.
	staged := stagedPurposes[in.Purpose] && !in.Compromised &&
		newestWithStatus(current, domain.SigningKeyActive) != nil
	status := domain.SigningKeyActive
	if staged {
		if newestWithStatus(current, domain.SigningKeyPending) != nil {
			return nil, ErrPendingKeyExists
		}
		status = domain.SigningKeyPending
	}

	newKey, err := GenerateSigningKey(ctx, s.km, s.keys, s.kmsBackend, GenerateSigningKeyParams{
		RealmID: in.RealmID,
		KeyType: keyType,
		Purpose: in.Purpose,
		Status:  status,
		Now:     s.now,
	})
	if err != nil {
		return nil, fmt.Errorf("key rotation: %w", err)
	}
	res.NewKey = newKey

	// From here on, keep going on errors: every step left undone is safe and
	// is redone by the next rotation; errors are returned together.
	var errs []error
	reason := in.Reason
	if staged {
		reason = joinReason(in.Reason, "staged: published, signs after activation")
	}
	if err := s.log(ctx, newKey.ID, domain.KeyRotationCreated, in.TriggeredBy, reason); err != nil {
		errs = append(errs, err)
	}
	if staged {
		// Nothing else changes now: the current key keeps signing. Activate
		// demotes it later, with the grace period known at that moment.
		res.Grace = 0
		if len(errs) > 0 {
			return res, fmt.Errorf("key rotation: new key %s is pending, but: %w", newKey.Kid, errors.Join(errs...))
		}
		return res, nil
	}

	retireAfter := s.now().Add(grace)
	for _, old := range current {
		if old.ID == newKey.ID || old.CreatedAt.After(newKey.CreatedAt) {
			continue // a concurrent, more recent rotation: leave it alone
		}

		if in.Compromised {
			// Every previous key goes, rotating ones included: in an
			// emergency we do not know how far the leak goes.
			err := s.keys.Retire(ctx, old.ID)
			if errors.Is(err, repository.ErrNotFound) {
				continue // already retired by someone else
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("retire key %s: %w", old.Kid, err))
				continue
			}
			old.Status, old.RetiredAt = domain.SigningKeyRetired, s.now()
			res.Retired = append(res.Retired, old)
			if err := s.log(ctx, old.ID, domain.KeyRotationCompromised, in.TriggeredBy, in.Reason); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		if old.Status != domain.SigningKeyActive {
			continue // already rotating: keep its original deadline
		}
		rotated, err := s.demote(ctx, old, newKey, retireAfter, in.TriggeredBy, in.Reason)
		if err != nil {
			errs = append(errs, err)
		}
		if rotated {
			res.Rotating = append(res.Rotating, old)
		}
	}

	if in.Compromised {
		res.Grace = 0
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("key rotation: new key %s is active, but: %w", newKey.Kid, errors.Join(errs...))
	}
	return res, nil
}

// demote moves one active key to "rotating" because newKey replaces it. It
// reports whether it did (false, nil: a concurrent rotation already did).
func (s *KeyRotationService) demote(ctx context.Context, old, newKey *domain.SigningKey, retireAfter time.Time, by, reason string) (bool, error) {
	err := s.keys.MarkRotating(ctx, old.ID, retireAfter)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil // demoted by a concurrent rotation
	}
	if err != nil {
		return false, fmt.Errorf("mark key %s rotating: %w", old.Kid, err)
	}
	old.Status, old.RetireAfter = domain.SigningKeyRotating, retireAfter
	if err := s.log(ctx, old.ID, domain.KeyRotationRotated, by, joinReason(reason, "superseded by kid "+newKey.Kid)); err != nil {
		return true, err
	}
	return true, nil
}

func joinReason(reason, detail string) string {
	if reason == "" {
		return detail
	}
	return reason + " (" + detail + ")"
}

// ActivateInput describes the second step of a two-step rotation.
type ActivateInput struct {
	RealmID string
	// Purpose defaults to saml_signing, the only two-step purpose.
	Purpose domain.SigningKeyPurpose
	// Grace of the previous key, which stops signing now. 0: the realm's
	// key_rotation_grace_hours. Assertions it signed only live minutes, but
	// the usual minimum still applies.
	Grace       time.Duration
	TriggeredBy string
	Reason      string
}

func (s *KeyRotationService) Activate(ctx context.Context, in ActivateInput) (*RotateResult, error) {
	if in.Purpose == "" {
		in.Purpose = domain.SigningKeyPurposeSAMLSigning
	}
	if in.RealmID == "" {
		return nil, errors.New("service: key activation needs a realm")
	}
	if in.TriggeredBy == "" {
		return nil, ErrRotationTriggeredByRequired
	}
	if !stagedPurposes[in.Purpose] {
		return nil, fmt.Errorf("%w: %q", ErrActivationNotSupported, in.Purpose)
	}
	grace, err := s.gracePeriod(ctx, RotateInput{RealmID: in.RealmID, Grace: in.Grace})
	if err != nil {
		return nil, err
	}

	keys, err := s.keys.ListActiveByRealm(ctx, in.RealmID)
	if err != nil {
		return nil, fmt.Errorf("key activation: list keys: %w", err)
	}
	keys = filterPurpose(keys, in.Purpose)
	pending := newestWithStatus(keys, domain.SigningKeyPending)
	if pending == nil {
		return nil, ErrNoPendingKey
	}
	if err := s.keys.Activate(ctx, pending.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNoPendingKey // activated or retired concurrently
		}
		return nil, fmt.Errorf("key activation: %w", err)
	}
	pending.Status = domain.SigningKeyActive
	res := &RotateResult{NewKey: pending, Grace: grace}

	var errs []error
	if err := s.log(ctx, pending.ID, domain.KeyRotationActivated, in.TriggeredBy, in.Reason); err != nil {
		errs = append(errs, err)
	}
	retireAfter := s.now().Add(grace)
	for _, old := range keys {
		if old.ID == pending.ID || old.Status != domain.SigningKeyActive || !old.CreatedAt.Before(pending.CreatedAt) {
			continue
		}
		rotated, err := s.demote(ctx, old, pending, retireAfter, in.TriggeredBy, in.Reason)
		if err != nil {
			errs = append(errs, err)
		}
		if rotated {
			res.Rotating = append(res.Rotating, old)
		}
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("key activation: key %s signs now, but: %w", pending.Kid, errors.Join(errs...))
	}
	return res, nil
}

// RetireExpired retires the "rotating" keys of a realm whose grace deadline
// has passed. It is idempotent: running it twice does nothing the second
// time. This is the function a cron will call later.
func (s *KeyRotationService) RetireExpired(ctx context.Context, realmID, triggeredBy string) ([]*domain.SigningKey, error) {
	if triggeredBy == "" {
		return nil, ErrRotationTriggeredByRequired
	}
	keys, err := s.keys.ListActiveByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("retire expired keys: list keys: %w", err)
	}

	now := s.now()
	var retired []*domain.SigningKey
	var errs []error
	for _, k := range keys {
		if k.Status != domain.SigningKeyRotating {
			continue
		}
		if k.RetireAfter.IsZero() {
			s.logger.WarnContext(ctx, "retire expired keys: rotating key without deadline, skipped",
				"realm_id", realmID, "kid", k.Kid)
			continue
		}
		if now.Before(k.RetireAfter) {
			continue // still in its grace period
		}
		err := s.keys.Retire(ctx, k.ID)
		if errors.Is(err, repository.ErrNotFound) {
			continue // retired concurrently
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("retire key %s: %w", k.Kid, err))
			continue
		}
		k.Status, k.RetiredAt = domain.SigningKeyRetired, now
		retired = append(retired, k)
		if err := s.log(ctx, k.ID, domain.KeyRotationRetired, triggeredBy, keyRotationReasonGraceEnded); err != nil {
			errs = append(errs, err)
		}
	}
	return retired, errors.Join(errs...)
}

// List returns every key of a realm (retired included), newest first.
func (s *KeyRotationService) List(ctx context.Context, realmID string) ([]*domain.SigningKey, error) {
	return s.keys.ListByRealm(ctx, realmID)
}

// GracePeriod returns the grace period configured for a realm.
func (s *KeyRotationService) GracePeriod(ctx context.Context, realmID string) (time.Duration, error) {
	settings, err := s.settings.GetByRealmID(ctx, realmID)
	if errors.Is(err, repository.ErrNotFound) {
		return DefaultKeyRotationGrace, nil
	}
	if err != nil {
		// Unlike the session policy, do not silently fall back: a rotation
		// is rare and deliberate, the operator should see the problem.
		return 0, fmt.Errorf("key rotation: read instance settings: %w", err)
	}
	if settings.KeyRotationGraceHours <= 0 {
		return DefaultKeyRotationGrace, nil
	}
	return time.Duration(settings.KeyRotationGraceHours) * time.Hour, nil
}

func (s *KeyRotationService) gracePeriod(ctx context.Context, in RotateInput) (time.Duration, error) {
	if in.Compromised {
		return 0, nil
	}
	grace := in.Grace
	if grace <= 0 {
		var err error
		if grace, err = s.GracePeriod(ctx, in.RealmID); err != nil {
			return 0, err
		}
	}
	if grace < MinKeyRotationGrace {
		return 0, fmt.Errorf("%w: %s (minimum %s)", ErrGraceTooShort, grace, MinKeyRotationGrace)
	}
	return grace, nil
}

func (s *KeyRotationService) validate(in RotateInput) error {
	if in.RealmID == "" {
		return errors.New("service: key rotation needs a realm")
	}
	if in.TriggeredBy == "" {
		return ErrRotationTriggeredByRequired
	}
	if !rotatablePurposes[in.Purpose] {
		return fmt.Errorf("%w: %q", ErrUnsupportedRotationPurpose, in.Purpose)
	}
	if in.Compromised && in.Reason == "" {
		return ErrCompromisedReasonRequired
	}
	if in.KeyType != "" {
		if _, err := toKeyManagerType(in.KeyType); err != nil {
			return err
		}
		if in.Purpose == domain.SigningKeyPurposeSAMLSigning && in.KeyType != domain.SigningKeyRSA {
			return ErrSAMLKeyMustBeRSA
		}
	}
	return nil
}

func (s *KeyRotationService) log(ctx context.Context, keyID string, action domain.KeyRotationAction, by, reason string) error {
	_, err := s.logs.Create(ctx, repository.CreateKeyRotationLogParams{
		SigningKeyID: keyID,
		Action:       action,
		TriggeredBy:  by,
		Reason:       reason,
	})
	if err != nil {
		return fmt.Errorf("write key rotation log (%s): %w", action, err)
	}
	return nil
}

func filterPurpose(keys []*domain.SigningKey, purpose domain.SigningKeyPurpose) []*domain.SigningKey {
	out := keys[:0:0]
	for _, k := range keys {
		if k.Purpose == purpose {
			out = append(out, k)
		}
	}
	return out
}

func newestWithStatus(keys []*domain.SigningKey, status domain.SigningKeyStatus) *domain.SigningKey {
	var best *domain.SigningKey
	for _, k := range keys {
		if k.Status == status && (best == nil || k.CreatedAt.After(best.CreatedAt)) {
			best = k
		}
	}
	return best
}
