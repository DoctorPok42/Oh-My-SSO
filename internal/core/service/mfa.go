package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/mfastore"
	"sso.internal/sso/internal/ratelimit"
)


const (
	loginChallengeTTL       = 5 * time.Minute
	maxLoginChallengeTries  = 5
	mfaAttemptsPerUser      = 10
	mfaAttemptsWindow       = 15 * time.Minute
	routeMFAVerifyRateLimit = "mfa.verify"
)

var (
	ErrMFAChallengeInvalid = errors.New("service: mfa challenge expired, already used or unknown")
	ErrMFAMethodNotAllowed = errors.New("service: this mfa method cannot answer this challenge")
	ErrMFARateLimited      = errors.New("service: too many mfa attempts, try again later")
	ErrMFARequiredByPolicy = errors.New("service: a policy requires mfa, the last allowed factor cannot be removed")
	ErrStepUpRequired      = errors.New("service: a recent authentication is required")
	// ErrMFAUnavailable: the user has second factors, but this server cannot
	// verify any of them (e.g. passkeys while WEBAUTHN_RP_ID is not set) and
	// no backup code is left. We refuse the login rather than skip MFA.
	ErrMFAUnavailable = errors.New("service: none of the user's second factors can be verified by this server")
)

// MFACodeError is ErrInvalidMFACode with the number of tries left on the
// login challenge (-1 when it does not apply, e.g. step-up).
type MFACodeError struct {
	AttemptsRemaining int
}

func (e *MFACodeError) Error() string { return ErrInvalidMFACode.Error() }
func (e *MFACodeError) Unwrap() error { return ErrInvalidMFACode }

// StepUpReason says what kind of recent authentication is missing.
type StepUpReason string

const (
	// StepUpNeedMFA: verify a second factor again (POST /auth/step-up).
	StepUpNeedMFA StepUpReason = "mfa"
	// StepUpNeedRecentLogin: the user has no factor; log in again.
	StepUpNeedRecentLogin StepUpReason = "recent_login"
	// StepUpNeedEnrollment: a policy demands MFA for this action but the
	// user has no factor that satisfies it.
	StepUpNeedEnrollment StepUpReason = "mfa_enrollment"
)

// StepUpRequiredError details ErrStepUpRequired.
type StepUpRequiredError struct {
	Reason         StepUpReason
	AllowedMethods []domain.MfaMethodType // nil: any of the user's factors
	MaxAge         time.Duration
}

func (e *StepUpRequiredError) Error() string {
	return fmt.Sprintf("%s (%s, max age %s)", ErrStepUpRequired, e.Reason, e.MaxAge)
}
func (e *StepUpRequiredError) Unwrap() error { return ErrStepUpRequired }

// StepUpMode picks the rule CheckStepUp applies.
type StepUpMode int

const (
	// StepUpAccountSecurity protects changes to the user's own factors.
	// Any of the user's factors may prove the user is there; a user without
	// any factor needs a recent login instead (otherwise nobody could ever
	// enroll a first factor).
	StepUpAccountSecurity StepUpMode = iota
	// StepUpSensitiveAction protects admin actions (signing keys today,
	// client changes later). Role policies may demand a second factor even
	// from users who have none, and may restrict the methods.
	StepUpSensitiveAction
)

// MFAService ties factors, policies, sessions and the challenge store.
type MFAService struct {
	users         repository.UserRepository
	methods       repository.MfaMethodRepository
	codes         repository.MfaBackupCodeRepository
	sessions      *SessionService
	policy        *MFAPolicyService
	envelope      *EnvelopeService
	store         mfastore.Store
	limiter       ratelimit.Limiter                 // optional
	loginAttempts repository.LoginAttemptRepository // optional
	audit         repository.AuditLogRepository     // optional
	realms        repository.RealmRepository        // optional: TOTP issuer name
	clients       repository.ClientRepository       // optional: client of a challenge
	passkeys      PasskeyProvider
	notifier      Notifier
	issuerName    string                            // optional override
	now           func() time.Time
	logger        *slog.Logger
}

// MFADeps groups the dependencies of NewMFAService.
type MFADeps struct {
	Users         repository.UserRepository
	Methods       repository.MfaMethodRepository
	BackupCodes   repository.MfaBackupCodeRepository
	Sessions      *SessionService
	Policy        *MFAPolicyService
	Envelope      *EnvelopeService
	Store         mfastore.Store
	Limiter       ratelimit.Limiter                 // optional
	LoginAttempts repository.LoginAttemptRepository // optional
	Audit         repository.AuditLogRepository     // optional
	Realms        repository.RealmRepository        // optional
	Clients       repository.ClientRepository       // optional
	// Passkeys is the WebAuthn engine (internal/passkey). nil: passkeys and
	// security keys are disabled.
	Passkeys PasskeyProvider
	Notifier Notifier
	// IssuerName overrides the name shown in authenticator apps
	// (default: the realm display name, or "Oh-My-SSO (<realm>)").
	IssuerName string
	Now        func() time.Time // optional (tests)
	Logger     *slog.Logger     // optional
}

func NewMFAService(d MFADeps) *MFAService {
	s := &MFAService{
		users:         d.Users,
		methods:       d.Methods,
		codes:         d.BackupCodes,
		sessions:      d.Sessions,
		policy:        d.Policy,
		envelope:      d.Envelope,
		store:         d.Store,
		limiter:       d.Limiter,
		loginAttempts: d.LoginAttempts,
		audit:         d.Audit,
		realms:        d.Realms,
		clients:       d.Clients,
		passkeys:      d.Passkeys,
		notifier:      d.Notifier,
		issuerName:    d.IssuerName,
		now:           d.Now,
		logger:        d.Logger,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.notifier == nil {
		s.notifier = NopNotifier{}
	}
	return s
}

// Policy exposes the policy service (HTTP handlers, IdentityCore).
func (s *MFAService) Policy() *MFAPolicyService { return s.policy }

// User loads a user (HTTP handlers of the account console).
func (s *MFAService) User(ctx context.Context, id string) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

// --- login --------------------------------------------------------------------

type LoginOutcome string

const (
	LoginAuthenticated         LoginOutcome = "authenticated"
	LoginMFARequired           LoginOutcome = "mfa_required"
	LoginMFAEnrollmentRequired LoginOutcome = "mfa_enrollment_required"
)

type BeginLoginInput struct {
	User      *domain.User      // password already verified
	Client    *domain.ClientApp // optional: the client the login is for
	IPAddress string
	UserAgent string
	DeviceFingerprint string
	// RememberMe ("Keep me signed in") is kept in the challenge, for the
	// session created after the second factor.
	RememberMe bool
}

// LoginDecision tells the caller what to do after a correct password.
type LoginDecision struct {
	Outcome LoginOutcome
	// Methods: for LoginMFARequired, the methods that may answer the
	// challenge; for LoginMFAEnrollmentRequired, the methods the user may
	// enroll (nil: any).
	Methods            []domain.MfaMethodType
	ChallengeToken     string // LoginMFARequired only: goes in the sso_mfa cookie
	ChallengeExpiresAt time.Time
	Requirement        MFARequirement
}

// BeginLogin decides, after a correct password, whether a second factor is
// needed. It never creates a session itself.
//
//   - The user has a factor: always challenged (they chose to protect their
//     account), restricted to the allowed methods when a policy requires
//     MFA and the user has one of them.
//   - No factor, a policy requires MFA: LoginMFAEnrollmentRequired. The
//     caller creates a session that can enroll a factor, but gets no
//     assertion for clients that require MFA.
//   - No factor, nothing required: LoginAuthenticated.
func (s *MFAService) BeginLogin(ctx context.Context, in BeginLoginInput) (*LoginDecision, error) {
	req, err := s.policy.Requirement(ctx, in.User, in.Client)
	if err != nil {
		return nil, err
	}
	all, err := s.answerableMethods(ctx, in.User.ID)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		// Fail closed: having factors that cannot be checked here must never
		// turn into "no MFA at all".
		factors, err := s.activeFactors(ctx, in.User.ID)
		if err != nil {
			return nil, err
		}
		if len(factors) > 0 {
			return nil, ErrMFAUnavailable
		}
	}

	if len(all) == 0 {
		if req.Required {
			return &LoginDecision{Outcome: LoginMFAEnrollmentRequired, Methods: req.AllowedMethods, Requirement: req}, nil
		}
		return &LoginDecision{Outcome: LoginAuthenticated, Requirement: req}, nil
	}

	methods := all
	if req.Required {
		if allowed := filterMethods(all, req); len(allowed) > 0 {
			methods = allowed
		}
	}

	token, expires, err := s.saveChallenge(ctx, in, methods)
	if err != nil {
		return nil, err
	}
	return &LoginDecision{
		Outcome:            LoginMFARequired,
		Methods:            methods,
		ChallengeToken:     token,
		ChallengeExpiresAt: expires,
		Requirement:        req,
	}, nil
}

func (s *MFAService) saveChallenge(ctx context.Context, in BeginLoginInput, methods []domain.MfaMethodType) (string, time.Time, error) {
	token := newRandomToken()
	now := s.now()
	c := mfastore.LoginChallenge{
		RealmID:    in.User.RealmID,
		UserID:     in.User.ID,
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
		Device:     in.DeviceFingerprint,
		Methods:    methodNames(methods),
		RememberMe: in.RememberMe,
		CreatedAt:  now,
		ExpiresAt:  now.Add(loginChallengeTTL),
	}
	if in.Client != nil {
		c.ClientRef = in.Client.ID
	}
	if err := s.store.SaveChallenge(ctx, HashSessionToken(token), c, loginChallengeTTL); err != nil {
		return "", time.Time{}, fmt.Errorf("mfa login: save challenge: %w", err)
	}
	return token, c.ExpiresAt, nil
}

type VerifyLoginInput struct {
	RealmID        string
	ChallengeToken string
	Method         string // "totp" or "backup_code"
	Code           string
	IPAddress      string
	UserAgent      string
}

// VerifiedLogin is the result of a successful second factor at login.
type VerifiedLogin struct {
	RawToken string // new session token, for the session cookie
	Session  *domain.Session
	User     *domain.User
	Method   domain.MfaMethodType
	// Outcome is LoginAuthenticated, or LoginMFAEnrollmentRequired when a
	// policy requires a method the user does not have yet.
	Outcome     LoginOutcome
	Requirement MFARequirement
	// BackupCodesRemaining is set when a backup code was used (-1 otherwise).
	BackupCodesRemaining int
}

func (s *MFAService) VerifyLogin(ctx context.Context, in VerifyLoginInput) (*VerifiedLogin, error) {
	lc, err := s.openChallenge(ctx, in.RealmID, in.ChallengeToken)
	if err != nil {
		return nil, err
	}
	method, ok := parseCodeMethod(in.Method)
	if !ok || !slices.Contains(lc.c.Methods, string(method)) {
		return nil, ErrMFAMethodNotAllowed
	}
	user, err := s.challengeUser(ctx, lc)
	if err != nil {
		return nil, err
	}

	valid, err := s.verifyCode(ctx, user, method, in.Code)
	if err != nil {
		return nil, err
	}
	if !valid {
		s.recordMFAFailure(ctx, user, in.IPAddress, in.UserAgent)
		return nil, &MFACodeError{AttemptsRemaining: lc.remaining()}
	}
	return s.finishLogin(ctx, lc, user, method, in.IPAddress, in.UserAgent)
}

// openedChallenge is a login challenge being answered.
type openedChallenge struct {
	key   string // hash of the token (store key)
	c     *mfastore.LoginChallenge
	tries int64
}

func (lc *openedChallenge) remaining() int { return maxLoginChallengeTries - int(lc.tries) }

// openChallenge loads a login challenge and counts one more answer to it.
// After maxLoginChallengeTries answers the challenge is burnt: back to the
// password.
func (s *MFAService) openChallenge(ctx context.Context, realmID, token string) (*openedChallenge, error) {
	if token == "" {
		return nil, ErrMFAChallengeInvalid
	}
	key := HashSessionToken(token)
	c, err := s.store.GetChallenge(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("mfa login: %w", err)
	}
	if c == nil || c.RealmID != realmID || !s.now().Before(c.ExpiresAt) {
		return nil, ErrMFAChallengeInvalid
	}
	tries, err := s.store.IncrementAttempts(ctx, key, c.ExpiresAt.Sub(s.now())+time.Second)
	if err != nil {
		return nil, fmt.Errorf("mfa login: %w", err)
	}
	if tries > maxLoginChallengeTries {
		_, _ = s.store.TakeChallenge(ctx, key)
		return nil, ErrMFAChallengeInvalid
	}
	return &openedChallenge{key: key, c: c, tries: tries}, nil
}

// challengeUser loads the user of a challenge. A user suspended between the
// two steps loses the challenge.
func (s *MFAService) challengeUser(ctx context.Context, lc *openedChallenge) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, lc.c.UserID)
	if err != nil || user.Status != domain.UserActive {
		_, _ = s.store.TakeChallenge(ctx, lc.key)
		return nil, ErrMFAChallengeInvalid
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// finishLogin consumes the challenge and creates the MFA-verified session.
func (s *MFAService) finishLogin(ctx context.Context, lc *openedChallenge, user *domain.User, method domain.MfaMethodType, ip, ua string) (*VerifiedLogin, error) {
	// Single use: if a concurrent request already finished this challenge,
	// stop here (its session is the only one).
	taken, err := s.store.TakeChallenge(ctx, lc.key)
	if err != nil {
		return nil, fmt.Errorf("mfa login: %w", err)
	}
	if !taken {
		return nil, ErrMFAChallengeInvalid
	}

	raw, sess, err := s.sessions.Create(ctx, CreateSessionInput{
		RealmID:           user.RealmID,
		UserID:            user.ID,
		IPAddress:         ip,
		UserAgent:         ua,
		AuthMethod:        domain.AuthMethodPassword,
		MFAVerified:       true,
		MFAMethodType:     string(method),
		DeviceFingerprint: lc.c.Device,
		RememberMe:        lc.c.RememberMe,
	})
	if err != nil {
		return nil, err
	}

	out := &VerifiedLogin{
		RawToken: raw, Session: sess, User: user, Method: method,
		Outcome: LoginAuthenticated, BackupCodesRemaining: -1,
	}
	var client *domain.ClientApp
	if lc.c.ClientRef != "" && s.clients != nil {
		client, _ = s.clients.GetByID(ctx, lc.c.ClientRef)
	}
	if req, err := s.policy.Requirement(ctx, user, client); err == nil {
		out.Requirement = req
		if req.Required && !req.Allows(method) {
			out.Outcome = LoginMFAEnrollmentRequired
		}
	}
	if method == domain.MfaMethodBackupCodes {
		if sum, err := s.backupCodesSummary(ctx, user.ID); err == nil {
			out.BackupCodesRemaining = sum.Remaining
		}
	}
	return out, nil
}

// --- step-up --------------------------------------------------------------------

// StepUp verifies a second factor for an existing session and upgrades it
// (same session id, same tokens). Used before sensitive actions, and when a
// client requires MFA that the session did not do yet.
func (s *MFAService) StepUp(ctx context.Context, sess *domain.Session, methodName, code, ip, ua string) (*domain.Session, domain.MfaMethodType, error) {
	method, ok := parseCodeMethod(methodName)
	if !ok {
		return nil, "", ErrMFAMethodNotAllowed
	}
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, "", fmt.Errorf("step-up: load user: %w", err)
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return nil, "", err
	}
	valid, err := s.verifyCode(ctx, user, method, code)
	if err != nil {
		return nil, "", err
	}
	if !valid {
		s.recordMFAFailure(ctx, user, ip, ua)
		return nil, "", &MFACodeError{AttemptsRemaining: -1}
	}
	upd, err := s.sessions.MarkMFAVerified(ctx, sess, string(method))
	if err != nil {
		return nil, "", err
	}
	return upd, method, nil
}

// CheckStepUp returns nil when the session has authenticated recently
// enough for the action, or a *StepUpRequiredError saying what is missing.
func (s *MFAService) CheckStepUp(ctx context.Context, sess *domain.Session, mode StepUpMode) error {
	_, err := s.CheckStepUpFor(ctx, sess, nil, mode)
	return err
}

// CheckStepUpFor is CheckStepUp for a caller that already loaded the
// session's user (nil: loaded here, when the mode needs it). It also returns
// the realm's step-up window (mfa_step_up_max_age_minutes), for the Admin
// API's /me. The realm's settings, the user and their factors are each read
// once.
func (s *MFAService) CheckStepUpFor(ctx context.Context, sess *domain.Session, user *domain.User, mode StepUpMode) (time.Duration, error) {
	settings, settingsErr := s.policy.realmSettings(ctx, sess.RealmID)
	maxAge := stepUpMaxAgeOf(settings) // the default if the read failed
	now := s.now()
	recentMFA := sess.MFAVerified && !sess.MFAVerifiedAt.IsZero() && now.Sub(sess.MFAVerifiedAt) <= maxAge
	recentLogin := now.Sub(sess.CreatedAt) <= maxAge

	factors, err := s.activeFactors(ctx, sess.UserID)
	if err != nil {
		return maxAge, err
	}

	switch mode {
	case StepUpAccountSecurity:
		if len(factors) > 0 {
			if recentMFA {
				return maxAge, nil
			}
			return maxAge, &StepUpRequiredError{Reason: StepUpNeedMFA, MaxAge: maxAge}
		}
		if recentLogin || recentMFA {
			return maxAge, nil
		}
		return maxAge, &StepUpRequiredError{Reason: StepUpNeedRecentLogin, MaxAge: maxAge}

	case StepUpSensitiveAction:
		if settingsErr != nil {
			return maxAge, settingsErr
		}
		if user == nil || user.ID != sess.UserID {
			if user, err = s.users.GetByID(ctx, sess.UserID); err != nil {
				return maxAge, fmt.Errorf("step-up: load user: %w", err)
			}
		}
		req, err := s.policy.requirementWith(ctx, user, nil, settings)
		if err != nil {
			return maxAge, err
		}
		needMFA := len(factors) > 0 || req.Required || req.StepUpForSensitiveActions
		if !needMFA {
			if recentLogin || recentMFA {
				return maxAge, nil
			}
			return maxAge, &StepUpRequiredError{Reason: StepUpNeedRecentLogin, MaxAge: maxAge}
		}
		answerable, err := s.answerableFrom(ctx, sess.UserID, factors)
		if err != nil {
			return maxAge, err
		}
		if len(filterMethods(answerable, req)) == 0 {
			return maxAge, &StepUpRequiredError{Reason: StepUpNeedEnrollment, AllowedMethods: req.AllowedMethods, MaxAge: maxAge}
		}
		if recentMFA && req.Allows(domain.MfaMethodType(sess.MFAMethodType)) {
			return maxAge, nil
		}
		return maxAge, &StepUpRequiredError{Reason: StepUpNeedMFA, AllowedMethods: req.AllowedMethods, MaxAge: maxAge}
	}
	return maxAge, fmt.Errorf("step-up: unknown mode %d", mode)
}

// CheckClientAccess enforces the MFA policy before an assertion is issued
// for a client. It returns nil or a *core.MFARequiredError.
func (s *MFAService) CheckClientAccess(ctx context.Context, sess *domain.Session, user *domain.User, client *domain.ClientApp) error {
	req, err := s.policy.Requirement(ctx, user, client)
	if err != nil {
		return err
	}
	if !req.Required {
		return nil
	}
	if sess.MFAVerified && req.Allows(domain.MfaMethodType(sess.MFAMethodType)) {
		return nil
	}
	answerable, err := s.answerableMethods(ctx, user.ID)
	if err != nil {
		return err
	}
	return &core.MFARequiredError{
		AllowedMethods:     req.AllowedMethods,
		EnrollmentRequired: len(filterMethods(answerable, req)) == 0,
	}
}

// MFAStatus describes where a session stands, for the UI and adapters.
type MFAStatus struct {
	Requirement        MFARequirement
	Satisfied          bool // the session meets the requirement
	EnrollmentRequired bool // required, but the user has no allowed factor
	EnrolledMethods    []domain.MfaMethodType
	VerifiedMethod     string
	VerifiedAt         time.Time
	StepUpMaxAge       time.Duration
	StepUpFresh        bool // MFA verified within StepUpMaxAge
}

func (s *MFAService) Status(ctx context.Context, sess *domain.Session, client *domain.ClientApp) (*MFAStatus, error) {
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("mfa status: load user: %w", err)
	}
	req, err := s.policy.Requirement(ctx, user, client)
	if err != nil {
		return nil, err
	}
	answerable, err := s.answerableMethods(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	maxAge := s.policy.StepUpMaxAge(ctx, sess.RealmID)
	st := &MFAStatus{
		Requirement:     req,
		EnrolledMethods: answerable,
		VerifiedMethod:  sess.MFAMethodType,
		VerifiedAt:      sess.MFAVerifiedAt,
		StepUpMaxAge:    maxAge,
		StepUpFresh:     sess.MFAVerified && !sess.MFAVerifiedAt.IsZero() && s.now().Sub(sess.MFAVerifiedAt) <= maxAge,
	}
	st.Satisfied = !req.Required || (sess.MFAVerified && req.Allows(domain.MfaMethodType(sess.MFAMethodType)))
	st.EnrollmentRequired = req.Required && len(filterMethods(answerable, req)) == 0
	return st, nil
}

// --- factor management -----------------------------------------------------

// FactorList is the account console view of the user's factors.
type FactorList struct {
	Methods     []*domain.MfaMethod // active factors (no pending enrollment)
	BackupCodes BackupCodesSummary
}

func (s *MFAService) ListFactors(ctx context.Context, userID string) (*FactorList, error) {
	factors, err := s.activeFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	sum, err := s.backupCodesSummary(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &FactorList{Methods: factors, BackupCodes: sum}, nil
}

// DeleteFactor removes one of the user's factors. Removing the last one also
// removes the backup codes (they are a fallback, not a factor on their own).
// It refuses to remove the last factor that satisfies a realm or role
// policy: the user would be locked into "enrollment required".
func (s *MFAService) DeleteFactor(ctx context.Context, user *domain.User, methodID string) error {
	m, err := s.methods.GetByID(ctx, methodID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMFAMethodNotFound
		}
		return fmt.Errorf("delete mfa factor: %w", err)
	}
	if m.UserID != user.ID {
		return ErrMFAMethodNotFound
	}

	if m.Status == domain.MfaMethodActive {
		factors, err := s.activeFactors(ctx, user.ID)
		if err != nil {
			return err
		}
		remaining := slices.DeleteFunc(factors, func(f *domain.MfaMethod) bool { return f.ID == m.ID })
		req, err := s.policy.Requirement(ctx, user, nil)
		if err != nil {
			return err
		}
		if req.Required {
			stillOK := false
			for _, f := range remaining {
				if req.Allows(f.Type) {
					stillOK = true
				}
			}
			if !stillOK {
				return ErrMFARequiredByPolicy
			}
		}
		if err := s.methods.Delete(ctx, m.ID); err != nil {
			return fmt.Errorf("delete mfa factor: %w", err)
		}
		if len(remaining) == 0 {
			if _, err := s.codes.DeleteByUser(ctx, user.ID); err != nil {
				return fmt.Errorf("delete mfa factor: backup codes: %w", err)
			}
		}
	} else if err := s.methods.Delete(ctx, m.ID); err != nil {
		return fmt.Errorf("delete mfa factor: %w", err)
	}

	s.auditEvent(ctx, user, "mfa_method_removed", "MfaMethod", m.ID, domain.AuditLogWarning, map[string]interface{}{
		"type": string(m.Type),
	})
	if m.Status == domain.MfaMethodActive {
		s.notify(ctx, user, domain.NotificationMfaMethodRemoved, m)
	}
	return nil
}

// ResetResult reports what an admin MFA reset removed.
type ResetResult struct {
	MethodsDeleted     int
	BackupCodesDeleted int
}

// ResetUser removes every factor and backup code of a user and revokes all
// their sessions (reason "mfa_reset"). It is the way out for someone who
// lost every factor. The user can log in with their password again and
// enroll new factors (subject to the policies).
func (s *MFAService) ResetUser(ctx context.Context, user *domain.User, triggeredBy, reason string) (*ResetResult, error) {
	n, err := s.methods.DeleteByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("mfa reset: %w", err)
	}
	c, err := s.codes.DeleteByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("mfa reset: %w", err)
	}
	if err := s.sessions.RevokeAllForUser(ctx, user.ID, domain.SessionRevokedMFAReset); err != nil {
		return nil, fmt.Errorf("mfa reset: %w", err)
	}
	if s.audit != nil {
		_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
			RealmID:      user.RealmID,
			UserID:       userIDFromTrigger(triggeredBy),
			Action:       "mfa_reset",
			ResourceType: "User",
			ResourceID:   user.ID,
			Level:        domain.AuditLogWarning,
			Status:       domain.AuditLogSuccess,
			Details: map[string]interface{}{
				"triggered_by":         triggeredBy,
				"reason":               reason,
				"methods_deleted":      n,
				"backup_codes_deleted": c,
			},
		})
	}
	if n > 0 {
		s.notify(ctx, user, domain.NotificationMfaReset, nil)
	}
	return &ResetResult{MethodsDeleted: n, BackupCodesDeleted: c}, nil
}

// VerifyCode checks (and consumes) a code of the user. Used by
// IdentityCore.VerifyMFA.
func (s *MFAService) VerifyCode(ctx context.Context, userID, methodName, code string) (domain.MfaMethodType, bool, error) {
	method, ok := parseCodeMethod(methodName)
	if !ok {
		return "", false, ErrMFAMethodNotAllowed
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", false, fmt.Errorf("verify mfa code: load user: %w", err)
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return "", false, err
	}
	valid, err := s.verifyCode(ctx, user, method, code)
	return method, valid, err
}

// --- internals ----------------------------------------------------------------

func (s *MFAService) verifyCode(ctx context.Context, user *domain.User, method domain.MfaMethodType, code string) (bool, error) {
	switch method {
	case domain.MfaMethodTOTP:
		return s.verifyTOTP(ctx, user, code)
	case domain.MfaMethodBackupCodes:
		// Backup codes only exist alongside a real factor.
		factors, err := s.activeFactors(ctx, user.ID)
		if err != nil || len(factors) == 0 {
			return false, err
		}
		return s.verifyBackupCode(ctx, user, code)
	default:
		return false, ErrMFAMethodNotAllowed
	}
}

// parseCodeMethod maps the API names of the code-based methods.
func parseCodeMethod(name string) (domain.MfaMethodType, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "totp":
		return domain.MfaMethodTOTP, true
	case "backup_code", "backup_codes":
		return domain.MfaMethodBackupCodes, true
	}
	return "", false
}

// activeFactors returns the user's usable factors (no pending enrollment).
func (s *MFAService) activeFactors(ctx context.Context, userID string) ([]*domain.MfaMethod, error) {
	all, err := s.methods.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list mfa factors: %w", err)
	}
	out := make([]*domain.MfaMethod, 0, len(all))
	for _, m := range all {
		if m.IsUsable() && m.Type != domain.MfaMethodBackupCodes {
			out = append(out, m)
		}
	}
	return out, nil
}

// answerableMethods lists the method types the user can answer a challenge
// with right now, in a stable order. Backup codes count only next to a real
// factor (even one this server cannot verify) and when some are left.
func (s *MFAService) answerableMethods(ctx context.Context, userID string) ([]domain.MfaMethodType, error) {
	factors, err := s.activeFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.answerableFrom(ctx, userID, factors)
}

// answerableFrom is answerableMethods with the active factors already loaded.
func (s *MFAService) answerableFrom(ctx context.Context, userID string, factors []*domain.MfaMethod) ([]domain.MfaMethodType, error) {
	var out []domain.MfaMethodType
	for _, t := range []domain.MfaMethodType{domain.MfaMethodTOTP, domain.MfaMethodPasskey, domain.MfaMethodWebAuthn} {
		if hasType(factors, t) && s.canVerify(t) {
			out = append(out, t)
		}
	}
	if len(factors) > 0 {
		sum, err := s.backupCodesSummary(ctx, userID)
		if err != nil {
			return nil, err
		}
		if sum.Remaining > 0 {
			out = append(out, domain.MfaMethodBackupCodes)
		}
	}
	return out, nil
}

// canVerify tells whether this server can verify a method type: passkeys
// and security keys need the WebAuthn configuration (WEBAUTHN_RP_ID).
func (s *MFAService) canVerify(t domain.MfaMethodType) bool {
	switch t {
	case domain.MfaMethodTOTP:
		return true
	case domain.MfaMethodPasskey, domain.MfaMethodWebAuthn:
		return s.passkeys != nil
	}
	return false
}

// newRandomToken returns a 26-character base32 token with 128 bits of
// randomness (same generator as session tokens).
func newRandomToken() string { return rand.Text() }

func filterMethods(methods []domain.MfaMethodType, req MFARequirement) []domain.MfaMethodType {
	var out []domain.MfaMethodType
	for _, m := range methods {
		if req.Allows(m) {
			out = append(out, m)
		}
	}
	return out
}

func (s *MFAService) allowAttempt(ctx context.Context, user *domain.User) error {
	if s.limiter == nil {
		return nil
	}
	ok, err := s.limiter.Allow(ctx,
		ratelimit.Key(routeMFAVerifyRateLimit, user.RealmID, "user", user.ID),
		mfaAttemptsPerUser, mfaAttemptsWindow)
	if err != nil {
		return fmt.Errorf("mfa rate limit: %w", err)
	}
	if !ok {
		return ErrMFARateLimited
	}
	return nil
}

func (s *MFAService) recordMFAFailure(ctx context.Context, user *domain.User, ip, ua string) {
	if s.loginAttempts == nil {
		return
	}
	_, _ = s.loginAttempts.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID:       user.RealmID,
		UserID:        user.ID,
		Identifier:    user.Username,
		IPAddress:     ip,
		UserAgent:     ua,
		Status:        domain.LoginAttemptFailure,
		FailureReason: domain.LoginFailureMfaFailed,
	})
}

func (s *MFAService) auditEvent(ctx context.Context, user *domain.User, action, resourceType, resourceID string, level domain.AuditLogLevel, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      user.RealmID,
		UserID:       user.ID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Level:        level,
		Status:       domain.AuditLogSuccess,
		Details:      details,
	})
}

func (s *MFAService) notify(ctx context.Context, user *domain.User, kind domain.NotificationKind, m *domain.MfaMethod) {
	e := domain.NotificationEvent{
		Kind:       kind,
		RealmID:    user.RealmID,
		UserID:     user.ID,
		OccurredAt: s.now(),
	}
	if m != nil {
		e.MfaMethodType = m.Type
		e.MfaMethodName = m.Name
	}
	s.notifier.Notify(ctx, e)
}

// issuer is the account label shown in authenticator apps. ":" is the
// separator of the otpauth:// label, so it is removed.
func (s *MFAService) issuer(ctx context.Context, realmID string) string {
	name := s.issuerName
	if name == "" && s.realms != nil {
		if r, err := s.realms.GetByID(ctx, realmID); err == nil {
			name = r.DisplayName
			if name == "" {
				name = "Oh-My-SSO (" + r.Name + ")"
			}
		}
	}
	if name == "" {
		name = "Oh-My-SSO"
	}
	return strings.ReplaceAll(name, ":", " ")
}
