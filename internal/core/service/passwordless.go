package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/mfastore"
)

// Sign-in without password (Step 18c).
//
// A passkey, or a security key such as a YubiKey, can replace the password
// when the authenticator verifies the user (biometrics or PIN): it is then
// two factors on its own, something you have (the private key never leaves
// the device) and something you are or know (what unlocks it). NIST SP
// 800-63B-4 accepts it at AAL2. A TOTP or a backup code never replaces the
// password: a 6-digit code only proves you hold the phone.
//
//	BeginPasswordlessLogin   options for navigator.credentials.get(), the
//	                         ceremony is kept 5 minutes under a random token
//	                         (an HttpOnly cookie of the browser)
//	FinishPasswordlessLogin  checks the answer, then the account (active, no
//	                         timeout) and creates an MFA-verified session
//
// The password lockout does not apply: it protects the password against
// guessing, and nobody can guess a passkey. A locked-out user can still
// sign in with their passkey (the lock stays on the password).

const ceremonyPasswordless = "passwordless"

// methodPriority is the order in which a sign-in offers the factors of a
// user, strongest first: a passkey or a security key resists phishing (it
// only answers the real site), a code from an authenticator app does not.
// Backup codes always come last (answerableFrom): they are the spare wheel.
var methodPriority = []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodWebAuthn, domain.MfaMethodTOTP}

// passwordlessKinds are the factor types that can sign in without password.
var passwordlessKinds = []domain.MfaMethodType{domain.MfaMethodPasskey, domain.MfaMethodWebAuthn}

var (
	// ErrNoPasskeyForSignIn: the account has no passkey or security key the
	// application accepts for a sign-in without password.
	ErrNoPasskeyForSignIn = errors.New("service: no passkey or security key can sign in to this application")
	// ErrPasskeySignInFailed: the authenticator's answer was refused. No
	// detail on purpose; the reason is in the server logs.
	ErrPasskeySignInFailed = errors.New("service: the passkey sign-in was refused")
)

// SignInMethods orders the first steps an account can take to sign in to
// client (nil: the IdP itself), best first: core.SignInPasskey when the user
// has a passkey or security key this server can check and the application
// accepts, then core.SignInPassword.
func (s *MFAService) SignInMethods(ctx context.Context, user *domain.User, client *domain.ClientApp) ([]core.SignInMethod, error) {
	out := make([]core.SignInMethod, 0, 2)
	types, err := s.passwordlessTypes(ctx, user, client)
	if err != nil {
		return nil, err
	}
	if len(types) > 0 {
		creds, err := s.webAuthnFactors(ctx, user.ID, types)
		if err != nil {
			return nil, err
		}
		if len(creds) > 0 {
			out = append(out, core.SignInPasskey)
		}
	}
	return append(out, core.SignInPassword), nil
}

// passwordlessTypes: the factor types that may sign in without password to
// client. Both kinds when the application does not require MFA; else only
// those its policy allows. A "TOTP only" application gets none: a passkey
// would not satisfy it, the user goes through password + TOTP.
func (s *MFAService) passwordlessTypes(ctx context.Context, user *domain.User, client *domain.ClientApp) ([]domain.MfaMethodType, error) {
	if s.passkeys == nil {
		return nil, nil
	}
	req, err := s.policy.Requirement(ctx, user, client)
	if err != nil {
		return nil, err
	}
	var out []domain.MfaMethodType
	for _, t := range passwordlessKinds {
		if !req.Required || req.Allows(t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// BeginPasswordlessInput starts a sign-in without password.
type BeginPasswordlessInput struct {
	RealmID string
	// User: the account of a "Pick an account" tile; only its credentials
	// may answer. nil: any discoverable passkey (the authenticator tells
	// whose it is).
	User   *domain.User
	Client *domain.ClientApp // optional: the application the sign-in is for
}

// PasswordlessCeremony is what the browser needs to answer.
type PasswordlessCeremony struct {
	Options   []byte // JSON for navigator.credentials.get()
	Token     string // goes in an HttpOnly cookie; FinishPasswordlessLogin needs it
	ExpiresAt time.Time
}

func passwordlessKey(token string) string {
	return ceremonyPasswordless + ":" + HashSessionToken(token)
}

// BeginPasswordlessLogin returns the options of a sign-in without password.
// For a tile, ErrNoPasskeyForSignIn when the account has nothing that can
// answer for this application (the page falls back to the password).
func (s *MFAService) BeginPasswordlessLogin(ctx context.Context, in BeginPasswordlessInput) (*PasswordlessCeremony, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	types := passwordlessKinds
	var creds []*domain.MfaMethod
	userID := ""
	if in.User != nil {
		if in.User.RealmID != in.RealmID || in.User.Status != domain.UserActive {
			return nil, ErrNoPasskeyForSignIn
		}
		var err error
		if types, err = s.passwordlessTypes(ctx, in.User, in.Client); err != nil {
			return nil, err
		}
		if len(types) > 0 {
			if creds, err = s.webAuthnFactors(ctx, in.User.ID, types); err != nil {
				return nil, err
			}
		}
		if len(creds) == 0 {
			return nil, ErrNoPasskeyForSignIn
		}
		userID = in.User.ID
	}

	options, state, err := s.passkeys.BeginPasswordlessLogin(in.User, creds)
	if err != nil {
		return nil, fmt.Errorf("passkey sign-in: %w", err)
	}
	token := newRandomToken()
	expires := s.now().Add(webAuthnCeremonyTTL)
	c := mfastore.Ceremony{
		Purpose: ceremonyPasswordless, RealmID: in.RealmID, UserID: userID, SessionData: state,
		Methods: methodNames(types), ExpiresAt: expires,
	}
	if in.Client != nil {
		c.ClientRef = in.Client.ID
	}
	if err := s.store.SaveCeremony(ctx, passwordlessKey(token), c, webAuthnCeremonyTTL); err != nil {
		return nil, fmt.Errorf("passkey sign-in: %w", err)
	}
	return &PasswordlessCeremony{Options: options, Token: token, ExpiresAt: expires}, nil
}

// FinishPasswordlessInput carries the browser's answer.
type FinishPasswordlessInput struct {
	RealmID           string
	Token             string // from the cookie set with the options
	Response          []byte // the PublicKeyCredential JSON
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	// RememberMe: "Keep me signed in" (a tile counts as ticked: the account
	// is only remembered on a device where it was ticked).
	RememberMe bool
}

// FinishPasswordlessLogin verifies the answer and creates the session:
// AuthMethod "hwk", MFAVerified, MFAMethodType the factor's type, so the
// OIDC amr is ["hwk", "mfa"] and SAML gets the REFEDS MFA context.
//
// Errors: ErrWebAuthnCeremonyInvalid (expired or already answered: ask for
// new options), ErrPasskeySignInFailed, ErrMFARateLimited,
// ErrAccountNotActive, ErrTimeoutActive.
func (s *MFAService) FinishPasswordlessLogin(ctx context.Context, in FinishPasswordlessInput) (*VerifiedLogin, error) {
	if s.passkeys == nil {
		return nil, ErrPasskeysDisabled
	}
	if in.Token == "" {
		return nil, ErrWebAuthnCeremonyInvalid
	}
	// Single use: a second answer (a replay, or a second tab) finds nothing.
	c, err := s.store.TakeCeremony(ctx, passwordlessKey(in.Token))
	if err != nil {
		return nil, fmt.Errorf("passkey sign-in: %w", err)
	}
	if c == nil || c.Purpose != ceremonyPasswordless || c.RealmID != in.RealmID || !s.now().Before(c.ExpiresAt) {
		return nil, ErrWebAuthnCeremonyInvalid
	}
	allowed := webAuthnTypesIn(c.Methods)

	var (
		creds   []*domain.MfaMethod
		limited error
	)
	owner := func(userID string) (*domain.User, []*domain.MfaMethod, error) {
		if c.UserID != "" && userID != c.UserID {
			return nil, nil, errors.New("the credential belongs to another user than the tile")
		}
		u, err := s.users.GetByID(ctx, userID)
		if err != nil {
			return nil, nil, fmt.Errorf("owner of the credential: %w", err)
		}
		// One RP ID for the whole server: the browser may offer a passkey of
		// another realm. It never signs in here.
		if u.RealmID != c.RealmID {
			return nil, nil, errors.New("the passkey belongs to another realm")
		}
		if err := s.allowAttempt(ctx, u); err != nil {
			limited = err
			return nil, nil, err
		}
		if creds, err = s.webAuthnFactors(ctx, u.ID, allowed); err != nil {
			return nil, nil, err
		}
		if len(creds) == 0 {
			return nil, nil, errors.New("the user has no passkey that may answer")
		}
		return u, creds, nil
	}

	user, a, err := s.passkeys.FinishPasswordlessLogin(c.SessionData, in.Response, owner)
	if limited != nil {
		return nil, limited
	}
	if err != nil {
		s.logger.InfoContext(ctx, "passkey sign-in rejected", "realm_id", in.RealmID, "error", err)
		if user != nil {
			s.recordSignIn(ctx, user, in, domain.LoginAttemptFailure, domain.LoginFailurePasskeyRejected)
		}
		return nil, ErrPasskeySignInFailed
	}

	var m *domain.MfaMethod
	for _, cand := range creds {
		if cand.CredentialID == a.CredentialID {
			m = cand
		}
	}
	switch {
	case m == nil, !a.UserVerified:
		// The library already refuses both; checked again on purpose: this
		// answer replaces the password.
		s.recordSignIn(ctx, user, in, domain.LoginAttemptFailure, domain.LoginFailurePasskeyRejected)
		return nil, ErrPasskeySignInFailed
	case a.CloneWarning:
		s.auditCloneWarning(ctx, user, m)
		s.recordSignIn(ctx, user, in, domain.LoginAttemptFailure, domain.LoginFailurePasskeyRejected)
		return nil, ErrPasskeySignInFailed
	}
	if err := s.methods.UpdateWebAuthnCredential(ctx, m.ID, a.CredentialJSON, s.now()); err != nil {
		return nil, fmt.Errorf("passkey sign-in: store credential: %w", err)
	}

	// The account itself is checked only now, like after a correct
	// password: its state is never revealed to someone without the passkey.
	if user.Status != domain.UserActive {
		s.recordSignIn(ctx, user, in, domain.LoginAttemptFailure, domain.LoginFailureAccountLocked)
		return nil, ErrAccountNotActive
	}
	blocked, err := s.timeouts.HasActiveTimeout(ctx, user.ID, c.ClientRef)
	if err != nil {
		return nil, fmt.Errorf("passkey sign-in: check timeout: %w", err)
	}
	if blocked {
		s.recordSignIn(ctx, user, in, domain.LoginAttemptFailure, domain.LoginFailureTimeoutActive)
		return nil, ErrTimeoutActive
	}

	raw, sess, err := s.sessions.Create(ctx, CreateSessionInput{
		RealmID:           user.RealmID,
		UserID:            user.ID,
		IPAddress:         in.IPAddress,
		UserAgent:         in.UserAgent,
		AuthMethod:        domain.AuthMethodHardwareKey,
		MFAVerified:       true,
		MFAMethodType:     string(m.Type),
		DeviceFingerprint: in.DeviceFingerprint,
		RememberMe:        in.RememberMe,
	})
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, user, in, domain.LoginAttemptSuccess, "")

	out := &VerifiedLogin{
		RawToken: raw, Session: sess, User: user, Method: m.Type,
		Outcome: LoginAuthenticated, BackupCodesRemaining: -1,
	}
	var client *domain.ClientApp
	if c.ClientRef != "" && s.clients != nil {
		client, _ = s.clients.GetByID(ctx, c.ClientRef)
	}
	if req, err := s.policy.Requirement(ctx, user, client); err == nil {
		out.Requirement = req
		// A discoverable passkey on an application that wants another
		// method: the session exists, the application's own check asks for
		// a step-up with an allowed factor, or for an enrollment when the
		// user has none.
		if req.Required && !req.Allows(m.Type) {
			if answerable, err := s.answerableMethods(ctx, user.ID); err == nil && len(filterMethods(answerable, req)) == 0 {
				out.Outcome = LoginMFAEnrollmentRequired
			}
		}
	}
	return out, nil
}

func (s *MFAService) recordSignIn(ctx context.Context, user *domain.User, in FinishPasswordlessInput, status domain.LoginAttemptStatus, reason domain.LoginAttemptFailureReason) {
	if s.loginAttempts == nil {
		return
	}
	_, _ = s.loginAttempts.Create(ctx, repository.CreateLoginAttemptParams{
		RealmID:       user.RealmID,
		UserID:        user.ID,
		Identifier:    user.Username,
		IPAddress:     in.IPAddress,
		UserAgent:     in.UserAgent,
		Status:        status,
		FailureReason: reason,
	})
}
