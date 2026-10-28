package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/mfastore"
)


type PasskeyKind string

const (
	// PasskeyKindPasskey: discoverable credential ("resident key") with user
	// verification (biometrics or device PIN). Stored as type "passkey". It
	// also signs in without password (Step 18c, passwordless.go).
	PasskeyKindPasskey PasskeyKind = "passkey"
	// PasskeyKindSecurityKey: classic WebAuthn second factor (e.g. a YubiKey),
	// not discoverable. Stored as type "webauthn".
	PasskeyKindSecurityKey PasskeyKind = "security_key"
)

const (
	webAuthnCeremonyTTL = 5 * time.Minute

	ceremonyRegister = "register"
	ceremonyLogin    = "login"
	ceremonyStepUp   = "step_up"
)

var (
	ErrPasskeysDisabled          = errors.New("service: passkeys are not configured on this server (WEBAUTHN_RP_ID)")
	ErrWebAuthnCeremonyInvalid   = errors.New("service: webauthn ceremony expired or already used, request new options")
	ErrPasskeyRegistrationFailed = errors.New("service: the authenticator response could not be verified")
	ErrPasskeyAlreadyRegistered  = errors.New("service: this authenticator is already registered")
	ErrUnknownPasskeyKind        = errors.New("service: unknown passkey kind (expected passkey or security_key)")
)

// PasskeyProvider is the WebAuthn engine (implemented by internal/passkey).
// Options and responses are the JSON the browser understands
// (PublicKeyCredentialCreationOptionsJSON / RegistrationResponseJSON...);
// state is opaque and only given back to the same provider.
type PasskeyProvider interface {
	// BeginRegistration: existing credentials are excluded, so the same
	// authenticator cannot be registered twice.
	BeginRegistration(user *domain.User, existing []*domain.MfaMethod, kind PasskeyKind) (options, state []byte, err error)
	FinishRegistration(user *domain.User, existing []*domain.MfaMethod, kind PasskeyKind, state, response []byte) (*NewPasskey, error)
	// BeginLogin: only the given credentials may answer.
	BeginLogin(user *domain.User, credentials []*domain.MfaMethod) (options, state []byte, err error)
	FinishLogin(user *domain.User, credentials []*domain.MfaMethod, state, response []byte) (*PasskeyAssertion, error)

	// BeginPasswordlessLogin: a sign-in without password, user verification
	// required. user nil: any discoverable passkey may answer (the
	// authenticator tells whose it is); else only the given credentials.
	BeginPasswordlessLogin(user *domain.User, credentials []*domain.MfaMethod) (options, state []byte, err error)
	// FinishPasswordlessLogin verifies the answer. owner gives the user a
	// credential belongs to and the credentials that may answer.
	FinishPasswordlessLogin(state, response []byte, owner PasskeyOwnerFunc) (*domain.User, *PasskeyAssertion, error)
}

// PasskeyOwnerFunc loads the user of a sign-in without password, from the
// user id of the options or the user handle of the authenticator (both are
// User.ID), with the credentials that may answer. An error refuses the
// answer.
type PasskeyOwnerFunc func(userID string) (*domain.User, []*domain.MfaMethod, error)

// NewPasskey is a verified registration, ready to store.
type NewPasskey struct {
	CredentialID   string // base64url
	PublicKey      string // base64 COSE key
	Discoverable   bool   // the authenticator created a discoverable credential
	BackupEligible bool   // synced passkey (iCloud Keychain, Google Password Manager...)
	CredentialJSON string // full record for the next logins
}

// PasskeyAssertion is a verified login.
type PasskeyAssertion struct {
	CredentialID   string // base64url, which credential answered
	CredentialJSON string // updated record (sign counter, backup state)
	// CloneWarning: the signature counter went backwards, two copies of the
	// private key may exist. We refuse the login.
	CloneWarning bool
	UserVerified bool
}

// PasskeysEnabled tells whether WebAuthn is configured.
func (s *MFAService) PasskeysEnabled() bool { return s.passkeys != nil }

// --- registration --------------------------------------------------------------

func ceremonyKeyFor(purpose, sessionID string) string { return purpose + ":" + sessionID }

// BeginPasskeyRegistration returns the options for navigator.credentials.create().
// The route calling it is protected by step-up (StepUpAccountSecurity).
func (s *MFAService) BeginPasskeyRegistration(ctx context.Context, user *domain.User, sess *domain.Session, kind PasskeyKind, name string) ([]byte, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	if kind != PasskeyKindPasskey && kind != PasskeyKindSecurityKey {
		return nil, ErrUnknownPasskeyKind
	}
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 100 {
		return nil, fmt.Errorf("%w: name too long (100 characters max)", ErrInvalidMFAPolicy)
	}
	existing, err := s.webAuthnFactors(ctx, user.ID, nil)
	if err != nil {
		return nil, err
	}
	options, state, err := s.passkeys.BeginRegistration(user, existing, kind)
	if err != nil {
		return nil, fmt.Errorf("passkey registration: %w", err)
	}
	err = s.store.SaveCeremony(ctx, ceremonyKeyFor(ceremonyRegister, sess.ID), mfastore.Ceremony{
		Purpose: ceremonyRegister, RealmID: user.RealmID, UserID: user.ID, SessionData: state,
		Kind: string(kind), Name: name, ExpiresAt: s.now().Add(webAuthnCeremonyTTL),
	}, webAuthnCeremonyTTL)
	if err != nil {
		return nil, fmt.Errorf("passkey registration: %w", err)
	}
	return options, nil
}

// FinishPasskeyRegistration verifies the authenticator's answer and stores
// the new factor. The first factor of a user also gets backup codes, and the
// session becomes MFA-verified (creating a credential with the new
// authenticator proves possession of it).
func (s *MFAService) FinishPasskeyRegistration(ctx context.Context, user *domain.User, sess *domain.Session, response []byte) (*EnrollmentResult, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	c, err := s.store.TakeCeremony(ctx, ceremonyKeyFor(ceremonyRegister, sess.ID))
	if err != nil {
		return nil, fmt.Errorf("passkey registration: %w", err)
	}
	if c == nil || c.Purpose != ceremonyRegister || c.UserID != user.ID {
		return nil, ErrWebAuthnCeremonyInvalid
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return nil, err
	}

	before, err := s.activeFactors(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	existing := slices.DeleteFunc(slices.Clone(before), func(m *domain.MfaMethod) bool { return !m.IsWebAuthn() })
	kind := PasskeyKind(c.Kind)
	np, err := s.passkeys.FinishRegistration(user, existing, kind, c.SessionData, response)
	if err != nil {
		s.logger.InfoContext(ctx, "passkey registration rejected", "user_id", user.ID, "error", err)
		return nil, fmt.Errorf("%w: %v", ErrPasskeyRegistrationFailed, err)
	}

	// What is stored is what the authenticator actually did, not what was
	// asked: a "passkey" request answered with a non-discoverable credential
	// is stored as a plain security key.
	t := domain.MfaMethodWebAuthn
	if np.Discoverable {
		t = domain.MfaMethodPasskey
	}
	m, err := s.methods.Create(ctx, repository.CreateMfaMethodParams{
		UserID:             user.ID,
		Type:               t,
		Name:               c.Name,
		Status:             domain.MfaMethodActive,
		CredentialID:       np.CredentialID,
		PublicKey:          np.PublicKey,
		IsDiscoverable:     np.Discoverable,
		WebAuthnCredential: np.CredentialJSON,
	})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, ErrPasskeyAlreadyRegistered
		}
		return nil, fmt.Errorf("passkey registration: %w", err)
	}

	res := &EnrollmentResult{Method: m, Session: sess}
	if len(before) == 0 {
		codes, err := s.replaceBackupCodes(ctx, user)
		if err != nil {
			return nil, err
		}
		res.BackupCodes = codes
	}
	upd, err := s.sessions.MarkMFAVerified(ctx, sess, string(t))
	if err != nil {
		return nil, err
	}
	res.Session = upd

	s.auditEvent(ctx, user, "mfa_method_enrolled", "MfaMethod", m.ID, domain.AuditLogInfo, map[string]interface{}{
		"type":            string(t),
		"requested":       string(kind),
		"backup_eligible": np.BackupEligible,
	})
	s.notify(ctx, user, domain.NotificationMfaMethodAdded, m)
	return res, nil
}

// --- second factor at login ---------------------------------------------------

func loginCeremonyKey(challengeKey string) string { return ceremonyLogin + ":" + challengeKey }

// BeginPasskeyLogin returns the options for navigator.credentials.get(),
// for the login challenge in the sso_mfa cookie.
func (s *MFAService) BeginPasskeyLogin(ctx context.Context, realmID, challengeToken string) ([]byte, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	if challengeToken == "" {
		return nil, ErrMFAChallengeInvalid
	}
	key := HashSessionToken(challengeToken)
	c, err := s.store.GetChallenge(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("passkey login: %w", err)
	}
	if c == nil || c.RealmID != realmID || !s.now().Before(c.ExpiresAt) {
		return nil, ErrMFAChallengeInvalid
	}
	allowed := webAuthnTypesIn(c.Methods)
	if len(allowed) == 0 {
		return nil, ErrMFAMethodNotAllowed
	}
	user, err := s.users.GetByID(ctx, c.UserID)
	if err != nil || user.Status != domain.UserActive {
		return nil, ErrMFAChallengeInvalid
	}
	creds, err := s.webAuthnFactors(ctx, user.ID, allowed)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrMFAMethodNotAllowed
	}
	options, state, err := s.passkeys.BeginLogin(user, creds)
	if err != nil {
		return nil, fmt.Errorf("passkey login: %w", err)
	}
	ttl := c.ExpiresAt.Sub(s.now())
	err = s.store.SaveCeremony(ctx, loginCeremonyKey(key), mfastore.Ceremony{
		Purpose: ceremonyLogin, RealmID: realmID, UserID: user.ID, SessionData: state,
		Methods: methodNames(allowed), ExpiresAt: c.ExpiresAt,
	}, ttl)
	if err != nil {
		return nil, fmt.Errorf("passkey login: %w", err)
	}
	return options, nil
}

type VerifyPasskeyLoginInput struct {
	RealmID        string
	ChallengeToken string
	Response       []byte // the PublicKeyCredential JSON sent by the browser
	IPAddress      string
	UserAgent      string
}

// FinishPasskeyLogin verifies the assertion and, like VerifyLogin, creates
// the MFA-verified session. Each answer counts as one try on the challenge.
func (s *MFAService) FinishPasskeyLogin(ctx context.Context, in VerifyPasskeyLoginInput) (*VerifiedLogin, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	lc, err := s.openChallenge(ctx, in.RealmID, in.ChallengeToken)
	if err != nil {
		return nil, err
	}
	c, err := s.store.TakeCeremony(ctx, loginCeremonyKey(lc.key))
	if err != nil {
		return nil, fmt.Errorf("passkey login: %w", err)
	}
	if c == nil || c.Purpose != ceremonyLogin || c.UserID != lc.c.UserID {
		return nil, ErrWebAuthnCeremonyInvalid
	}
	user, err := s.challengeUser(ctx, lc)
	if err != nil {
		return nil, err
	}

	m, err := s.verifyAssertion(ctx, user, webAuthnTypesIn(c.Methods), c.SessionData, in.Response)
	if err != nil {
		if errors.Is(err, ErrInvalidMFACode) {
			s.recordMFAFailure(ctx, user, in.IPAddress, in.UserAgent)
			return nil, &MFACodeError{AttemptsRemaining: lc.remaining()}
		}
		return nil, err
	}
	return s.finishLogin(ctx, lc, user, m.Type, in.IPAddress, in.UserAgent)
}

// --- step-up --------------------------------------------------------------------

// BeginPasskeyStepUp returns options to verify one of the user's passkeys or
// security keys again, for the current session.
func (s *MFAService) BeginPasskeyStepUp(ctx context.Context, sess *domain.Session) ([]byte, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("passkey step-up: load user: %w", err)
	}
	creds, err := s.webAuthnFactors(ctx, user.ID, nil)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrMFAMethodNotAllowed
	}
	options, state, err := s.passkeys.BeginLogin(user, creds)
	if err != nil {
		return nil, fmt.Errorf("passkey step-up: %w", err)
	}
	err = s.store.SaveCeremony(ctx, ceremonyKeyFor(ceremonyStepUp, sess.ID), mfastore.Ceremony{
		Purpose: ceremonyStepUp, RealmID: user.RealmID, UserID: user.ID, SessionData: state,
		Methods:   []string{string(domain.MfaMethodPasskey), string(domain.MfaMethodWebAuthn)},
		ExpiresAt: s.now().Add(webAuthnCeremonyTTL),
	}, webAuthnCeremonyTTL)
	if err != nil {
		return nil, fmt.Errorf("passkey step-up: %w", err)
	}
	return options, nil
}

// FinishPasskeyStepUp verifies the assertion and upgrades the session.
func (s *MFAService) FinishPasskeyStepUp(ctx context.Context, sess *domain.Session, response []byte, ip, ua string) (*domain.Session, domain.MfaMethodType, error) {
	if s.passkeys == nil {
		return nil, "", ErrPasskeysDisabled
	}
	c, err := s.store.TakeCeremony(ctx, ceremonyKeyFor(ceremonyStepUp, sess.ID))
	if err != nil {
		return nil, "", fmt.Errorf("passkey step-up: %w", err)
	}
	if c == nil || c.Purpose != ceremonyStepUp || c.UserID != sess.UserID {
		return nil, "", ErrWebAuthnCeremonyInvalid
	}
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, "", fmt.Errorf("passkey step-up: load user: %w", err)
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return nil, "", err
	}
	m, err := s.verifyAssertion(ctx, user, webAuthnTypesIn(c.Methods), c.SessionData, response)
	if err != nil {
		if errors.Is(err, ErrInvalidMFACode) {
			s.recordMFAFailure(ctx, user, ip, ua)
			return nil, "", &MFACodeError{AttemptsRemaining: -1}
		}
		return nil, "", err
	}
	upd, err := s.sessions.MarkMFAVerified(ctx, sess, string(m.Type))
	if err != nil {
		return nil, "", err
	}
	return upd, m.Type, nil
}

// --- internals ----------------------------------------------------------------

// verifyAssertion checks a WebAuthn assertion against the user's credentials
// of the allowed types and stores the updated credential record. Any
// verification failure is reported as ErrInvalidMFACode (no detail leaks to
// the client; the reason is logged).
func (s *MFAService) verifyAssertion(ctx context.Context, user *domain.User, allowed []domain.MfaMethodType, state, response []byte) (*domain.MfaMethod, error) {
	creds, err := s.webAuthnFactors(ctx, user.ID, allowed)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrInvalidMFACode
	}
	a, err := s.passkeys.FinishLogin(user, creds, state, response)
	if err != nil {
		s.logger.InfoContext(ctx, "passkey assertion rejected", "user_id", user.ID, "error", err)
		return nil, ErrInvalidMFACode
	}
	var m *domain.MfaMethod
	for _, cand := range creds {
		if cand.CredentialID == a.CredentialID {
			m = cand
		}
	}
	if m == nil {
		return nil, ErrInvalidMFACode
	}
	if a.CloneWarning {
		s.auditCloneWarning(ctx, user, m)
		return nil, ErrInvalidMFACode
	}
	if err := s.methods.UpdateWebAuthnCredential(ctx, m.ID, a.CredentialJSON, s.now()); err != nil {
		return nil, fmt.Errorf("passkey: store credential: %w", err)
	}
	return m, nil
}

// auditCloneWarning records a signature counter that went backwards: two
// copies of the private key may exist.
func (s *MFAService) auditCloneWarning(ctx context.Context, user *domain.User, m *domain.MfaMethod) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID: user.RealmID, UserID: user.ID, Action: "mfa_passkey_clone_warning",
		ResourceType: "MfaMethod", ResourceID: m.ID,
		Level: domain.AuditLogCritical, Status: domain.AuditLogFailure,
		Details: map[string]interface{}{"type": string(m.Type)},
	})
}

// webAuthnFactors returns the user's active passkeys / security keys,
// restricted to the given types (nil: both).
func (s *MFAService) webAuthnFactors(ctx context.Context, userID string, types []domain.MfaMethodType) ([]*domain.MfaMethod, error) {
	factors, err := s.activeFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []*domain.MfaMethod
	for _, f := range factors {
		if f.IsWebAuthn() && (types == nil || slices.Contains(types, f.Type)) {
			out = append(out, f)
		}
	}
	return out, nil
}

func webAuthnTypesIn(methods []string) []domain.MfaMethodType {
	var out []domain.MfaMethodType
	for _, m := range methods {
		if t := domain.MfaMethodType(m); t == domain.MfaMethodPasskey || t == domain.MfaMethodWebAuthn {
			out = append(out, t)
		}
	}
	return out
}
