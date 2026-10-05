// Package core defines the stable, protocol-agnostic contract between the IdP
// core and the protocol adapters (OIDC, SAML, ...).
//
// Adapters must only depend on this package and on internal/core/domain.
// They never talk to repositories, Ent, Valkey or the KeyManager directly:
// every operation goes through IdentityCore.
//
// Nothing in this package knows what a JWT or a SAML XML document is.
package core

import (
	"context"
	"errors"
	"time"

	"sso.internal/sso/internal/core/domain"
)

// Errors adapters are expected to recognise with errors.Is.
var (
	ErrInvalidCredentials  = errors.New("core: invalid credentials")
	ErrAccountNotActive    = errors.New("core: account not active")
	ErrTimeoutActive       = errors.New("core: an active timeout blocks this user or client")
	ErrSessionInvalid      = errors.New("core: session invalid")
	ErrForbidden           = errors.New("core: forbidden")
	ErrMFANotImplemented   = errors.New("core: mfa verification not implemented yet")
	ErrNoActiveSigningKey  = errors.New("core: no active signing key")
	ErrClientMisconfigured = errors.New("core: client misconfigured")
)

// Credentials is the input of a local (username/email + password) login.
type Credentials struct {
	RealmID    string
	Identifier string // username or email
	Password   string
	IPAddress  string
	UserAgent  string
	// ClientRef is the ClientApp.ID the user is logging in for, when known
	// (OIDC/SAML flows). Empty for a direct login on the IdP itself.
	ClientRef string
}

// AuthContext describes how a user authenticated, to create a session.
type AuthContext struct {
	RealmID       string
	IPAddress     string
	UserAgent     string
	AuthMethod    string // "password" today; more values after Step 9
	MFAVerified   bool
	MFAMethodType string
}

// IssuedSession is returned once, at session creation.
//
// RawToken only exists in memory: the database stores its hash. The caller
// must put it in the session cookie right away; it can never be recovered.
type IssuedSession struct {
	RawToken string
	Session  *domain.Session
}

// MFAChallenge is the user's answer to a second-factor challenge.
// Placeholder: fields will be refined at Step 9 (TOTP, WebAuthn, backup codes).
// Adding fields to a struct does not break the interface.
type MFAChallenge struct {
	Method   string
	Response string
}

// IdentityAssertion is the neutral "identity card" handed to adapters.
//
// Every field has an equivalent in both protocols, e.g.
//   - Subject   -> "sub" (OIDC)       / <Subject><NameID> (SAML)
//   - Audience  -> "aud" (OIDC)       / <Audience> (SAML)
//   - AuthTime  -> "auth_time" (OIDC) / AuthnInstant (SAML)
//
// The OIDC adapter turns it into a signed id_token, the SAML adapter into a
// signed <saml:Assertion>.
type IdentityAssertion struct {
	Subject     string // User.ID — stable, never the email
	Audience    string // client_id (OIDC) or entity_id (SAML)
	IssuedAt    time.Time
	ExpiresAt   time.Time // never later than the session's own expiry
	AuthTime    time.Time // when the user actually logged in (Session.CreatedAt)
	AuthMethod  string
	MFAVerified bool
	SessionID   string
	ClientRef   string // ClientApp.ID the assertion was issued for

	// Claims holds neutral user attributes (username, email, ...).
	Claims map[string]any

	// Scopes are the effective client scopes, already filtered by what the
	// client requested. Adapters apply each scope's ClaimMappers, which are
	// protocol-specific.
	Scopes []*domain.ClientScope
}

// Signer signs payloads with one specific key.
//
// It exists because a JWT header (and a SAML SignedInfo block) contains the
// key id and the algorithm, and that header is itself part of the signed
// bytes: an adapter must know KeyID and KeyType BEFORE it signs.
type Signer interface {
	KeyID() string                  // JWT header "kid" / SAML KeyInfo
	KeyType() domain.SigningKeyType // RSA or EC -> adapter picks "RS256" / "ES256"
	// Sign hashes payload with SHA-256 and signs it. EC signatures are
	// ASN.1 DER encoded; JOSE "ES256" needs raw r||s (adapter's job).
	Sign(ctx context.Context, payload []byte) ([]byte, error)
}

// IdentityCore is the only entry point adapters use.
type IdentityCore interface {
	// --- Authentication ---

	// AuthenticateLocal checks credentials, the account status and active
	// timeouts. It records a LoginAttempt in every case.
	AuthenticateLocal(ctx context.Context, c Credentials) (*domain.User, error)
	// VerifyMFA returns ErrMFANotImplemented until Step 9.
	VerifyMFA(ctx context.Context, userID string, ch MFAChallenge) (bool, error)

	// --- Sessions ---

	CreateSession(ctx context.Context, userID string, ac AuthContext) (*IssuedSession, error)
	// ValidateSession is the front-channel check: the browser is there and
	// sends its cookie (raw token). It refreshes the activity timestamp.
	ValidateSession(ctx context.Context, realmID, rawToken string) (*domain.Session, error)
	// GetSession is the back-channel lookup: server-to-server call, no
	// cookie, only the session id. It does NOT refresh activity.
	GetSession(ctx context.Context, sessionID string) (*domain.Session, error)
	RevokeSession(ctx context.Context, sessionID string, reason domain.SessionRevokedReason) error

	// --- Identity assertions (format-agnostic) ---

	// IssueIdentityAssertion checks the session, the user's right to access
	// the client and active timeouts, then builds the neutral assertion.
	// An empty requestedScopes means "all effective scopes".
	IssueIdentityAssertion(ctx context.Context, sessionID, clientRef string, requestedScopes []string) (*IdentityAssertion, error)

	// --- Authorization ---

	GetEffectivePermissions(ctx context.Context, userID, clientRef string) ([]*domain.Permission, error)
	IsAuthorizedForClient(ctx context.Context, userID, clientRef string) (bool, error)

	// --- Tokens ---

	// RevokeToken is idempotent: an unknown jti is not an error.
	RevokeToken(ctx context.Context, jti string) error
	// IsTokenRevoked fails closed: an unknown jti is reported as revoked.
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)

	// --- Keys ---

	// Signer returns the newest active key of the realm for that purpose.
	Signer(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) (Signer, error)
}
