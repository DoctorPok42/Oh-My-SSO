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
	ErrMFANotImplemented   = errors.New("core: mfa verification not configured")
	ErrMFARequired         = errors.New("core: multi-factor authentication required")
	ErrNoActiveSigningKey  = errors.New("core: no active signing key")
	ErrClientMisconfigured = errors.New("core: client misconfigured")

	// Step 10 (protocol clients and tokens).
	ErrClientNotFound      = errors.New("core: client not found")
	ErrInvalidClientSecret = errors.New("core: invalid client credentials")
	ErrTokenInvalid        = errors.New("core: token invalid")
	// ErrTokenReused: a refresh token that was already exchanged came back.
	// Somebody holds a copy: every token of its family has been revoked.
	ErrTokenReused = errors.New("core: refresh token reused, token family revoked")
)

// About the two MFA errors:
//   - ErrMFANotImplemented: VerifyMFA was called on an IdentityCore built
//     without the MFA service (Step 9 wiring missing).
//   - ErrMFARequired: the session does not satisfy the MFA policy of the
//     client, of the user's roles or of the realm. Use errors.As with
//     *MFARequiredError to know which methods are accepted.

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
	AuthMethod    string // RFC 8176 value, e.g. domain.AuthMethodPassword ("pwd")
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

// MFAChallenge is the user's answer to a code-based second-factor
// challenge. WebAuthn/passkey answers are not codes: they go through their
// own ceremony (Step 9b).
type MFAChallenge struct {
	Method   string // "totp" or "backup_code"
	Response string // the code typed by the user
}

// MFARequiredError details ErrMFARequired for the protocol adapters: the
// adapter sends the user to the step-up page (same session, no new login)
// or, when EnrollmentRequired, to the MFA enrollment page.
type MFARequiredError struct {
	// AllowedMethods that satisfy the requirement. nil: any method.
	AllowedMethods []domain.MfaMethodType
	// EnrollmentRequired: the user has no factor that satisfies the
	// requirement yet, they must enroll one first.
	EnrollmentRequired bool
}

func (e *MFARequiredError) Error() string {
	if e.EnrollmentRequired {
		return "core: multi-factor authentication required (enrollment needed)"
	}
	return ErrMFARequired.Error()
}

func (e *MFARequiredError) Unwrap() error { return ErrMFARequired }

// IdentityAssertion is the neutral "identity card" handed to adapters.
//
// Every field has an equivalent in both protocols, e.g.
//   - Subject     -> "sub" (OIDC)       / <Subject><NameID> (SAML)
//   - Audience    -> "aud" (OIDC)       / <Audience> (SAML)
//   - AuthTime    -> "auth_time" (OIDC) / AuthnInstant (SAML)
//   - AuthMethods -> "amr" (OIDC)       / AuthnContextClassRef (SAML, mapped)
//
// The OIDC adapter turns it into a signed id_token, the SAML adapter into a
// signed <saml:Assertion>.
type IdentityAssertion struct {
	// Subject is what the client sees as the user's identifier. It is stable
	// and never the email. Depending on ClientApp.SubjectType it is either
	// User.ID ("public") or a per-sector pairwise value ("pairwise").
	Subject   string
	Audience  string // client_id (OIDC) or entity_id (SAML)
	IssuedAt  time.Time
	ExpiresAt time.Time // never later than the session's own expiry
	AuthTime  time.Time // when the user actually logged in (Session.CreatedAt)
	// AuthMethods are RFC 8176 values, ready for the OIDC "amr" claim,
	// e.g. ["pwd"] or ["pwd", "otp", "mfa"].
	AuthMethods []string
	MFAVerified bool
	SessionID   string
	ClientRef   string // ClientApp.ID the assertion was issued for

	// UserID is the internal User.ID, for the adapter's own bookkeeping
	// (tokens, consents). NEVER emit it: use Subject.
	UserID string

	// UserAttributes are the raw user attributes. NEVER emit them as-is:
	// only what the adapter's claim mapping selects may leave the IdP
	// (minimal disclosure, OIDC Core §5.4). Keys:
	//
	//	username, email   string
	//	updated_at        int64 (Unix seconds)
	//	groups, roles     []string, names of the user's active groups / roles
	//	profile.<key>     every key of User.Profile, e.g. "profile.given_name"
	UserAttributes map[string]any

	// Scopes are the effective client scopes, already filtered by what the
	// client requested (plus the realm's is_default scopes, always kept).
	// Adapters apply each scope's ClaimMappers, which are protocol-specific.
	Scopes []*domain.ClientScope
}

// ProtocolClient is a client app as a protocol adapter sees it.
type ProtocolClient struct {
	App *domain.ClientApp
	// Scopes are the ClientScopes mapped to the client (ClientScopeMapping):
	// the custom scopes it may request. The standard OIDC scopes ("openid",
	// "profile", "email"...) are listed in App.AllowedScopes instead.
	Scopes []*domain.ClientScope
}

// TokenRequest describes the tokens to issue for one session and one client.
type TokenRequest struct {
	SessionID string
	ClientRef string // ClientApp.ID
	Scopes    []string
	// WithRefreshToken also issues a refresh token, the first of a new
	// token family.
	WithRefreshToken bool
}

// IssuedTokens is returned once, when tokens are created.
//
// RefreshToken only exists in memory: the database stores its SHA-256. The
// adapter hands it to the client right away; it can never be recovered.
type IssuedTokens struct {
	FamilyID string
	// Access is the access token record: its JTI goes into the JWT "jti"
	// claim and its ExpiresAt into "exp".
	Access *domain.Token
	// RefreshToken is empty when no refresh token was issued.
	RefreshToken string
	Refresh      *domain.Token
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
	// VerifyMFA checks (and consumes) a TOTP or backup code of the user.
	// A valid code can never be accepted twice. It does not touch any
	// session: callers decide what a successful verification unlocks.
	VerifyMFA(ctx context.Context, userID string, ch MFAChallenge) (bool, error)

	// --- Sessions ---

	CreateSession(ctx context.Context, userID string, ac AuthContext) (*IssuedSession, error)
	// ValidateSession is the front-channel check: the browser is there and
	// sends its cookie (raw token). It refreshes the activity timestamp.
	ValidateSession(ctx context.Context, realmID, rawToken string) (*domain.Session, error)
	// GetSession is the back-channel lookup: server-to-server call, no
	// cookie, only the session id. It does NOT refresh activity.
	GetSession(ctx context.Context, sessionID string) (*domain.Session, error)
	// RevokeSession also revokes every token issued for that session.
	RevokeSession(ctx context.Context, sessionID string, reason domain.SessionRevokedReason) error

	// --- Identity assertions (format-agnostic) ---

	// IssueIdentityAssertion checks the session, the user's right to access
	// the client, active timeouts and the MFA policy (*MFARequiredError),
	// then builds the neutral assertion.
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

	// IssueTokens records a new access token, and a refresh token when
	// asked, for an active session. The client must be allowed for the user
	// (RBAC, timeouts). Lifetimes come from the client and never go past the
	// session's own expiry. Call it right after IssueIdentityAssertion, which
	// also enforces the MFA policy.
	IssueTokens(ctx context.Context, req TokenRequest) (*IssuedTokens, error)
	// InspectRefreshToken returns the record of a raw refresh token without
	// consuming it. Unknown, expired, revoked or not a refresh token:
	// ErrTokenInvalid. Already exchanged: it is a replay, the whole family
	// is revoked and ErrTokenReused returned.
	InspectRefreshToken(ctx context.Context, rawToken string) (*domain.Token, error)
	// RotateRefreshToken exchanges a refresh token exactly once (two
	// concurrent calls: one wins, the other gets ErrTokenReused). It counts
	// as activity on the session, then issues a new access + refresh token
	// pair in the same family. nil scopes: the same scopes as before.
	RotateRefreshToken(ctx context.Context, rawToken, clientRef string, scopes []string) (*IssuedTokens, error)
	// LookupToken returns a token record by its jti. Unknown jti:
	// ErrTokenInvalid. It does NOT check revocation or expiry: callers do.
	LookupToken(ctx context.Context, jti string) (*domain.Token, error)
	// RevokeTokenFamily revokes every token of a family. Idempotent.
	RevokeTokenFamily(ctx context.Context, familyID string) error

	// --- Protocol clients (Step 10) ---

	// LookupClient finds an active client of the realm by its protocol
	// identifier: the OIDC client_id or the SAML entity_id. A deleted,
	// inactive or unknown client is ErrClientNotFound.
	LookupClient(ctx context.Context, realmID string, protocol domain.ClientAppProtocol, protocolID string) (*ProtocolClient, error)
	// AuthenticateClient checks the secret of a confidential client, in
	// constant time. Wrong secret, or a client without a secret (public):
	// ErrInvalidClientSecret.
	AuthenticateClient(ctx context.Context, clientRef, secret string) error

	// --- Keys ---

	// Signer returns the newest active key of the realm for that purpose.
	Signer(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) (Signer, error)
	// PublicKeys returns the keys whose public part must be published so
	// that clients can verify signatures: the "active" keys plus the
	// "rotating" keys still inside their grace period. Newest first.
	// The OIDC adapter publishes the jwt_signing ones as a JWKS, the SAML
	// adapter the saml_signing ones in its metadata.
	PublicKeys(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) ([]*domain.SigningKey, error)
}
