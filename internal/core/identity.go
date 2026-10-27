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
	ErrInvalidCredentials = errors.New("core: invalid credentials")
	ErrAccountNotActive   = errors.New("core: account not active")
	ErrTimeoutActive      = errors.New("core: an active timeout blocks this user or client")
	ErrAccountLocked       = errors.New("core: too many failed sign-ins, try again later")
	ErrSessionInvalid      = errors.New("core: session invalid")
	ErrForbidden           = errors.New("core: forbidden")
	ErrMFANotImplemented   = errors.New("core: mfa verification not configured")
	ErrMFARequired         = errors.New("core: multi-factor authentication required")
	ErrNoActiveSigningKey  = errors.New("core: no active signing key")
	ErrClientMisconfigured = errors.New("core: client misconfigured")

	ErrClientNotFound      = errors.New("core: client not found")
	ErrInvalidClientSecret = errors.New("core: invalid client credentials")
	ErrTokenInvalid        = errors.New("core: token invalid")
	// ErrTokenReused: a refresh token that was already exchanged came back.
	// Somebody holds a copy: every token of its family has been revoked.
	ErrTokenReused = errors.New("core: refresh token reused, token family revoked")

	ErrConsentNotConfigured = errors.New("core: user consent required but not configured")
)


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
	// RememberMe asks for a remembered session ("Keep me signed in");
	// ignored when the realm does not offer it.
	RememberMe bool
}

// SessionOptions is what the sign-in page of a realm may offer.
type SessionOptions struct {
	// RememberMe: show "Keep me signed in". A remembered session lasts
	// RememberMeMaxAge at most.
	RememberMe       bool
	RememberMeMaxAge time.Duration
}

// Account is an account shown on the sign-in page ("Pick an account").
type Account struct {
	// ID of the known account ("Forget" needs it). Empty for the account of
	// the current session when it is not remembered on this device.
	ID       string
	Name     string // display name: given + family name, else the username
	Email    string
	Username string
	// Identifier pre-fills the "Username or e-mail" field: the e-mail when
	// the account has one, else the username.
	Identifier string
	// SignedIn: the browser's current session belongs to this account.
	SignedIn bool
}

// AccountQuery asks for the accounts to show on a device.
type AccountQuery struct {
	RealmID string
	// DeviceID is the raw value of the sso_device cookie ("" or malformed:
	// no remembered account).
	DeviceID string
	// Current is the browser's valid session, or nil. Its account comes
	// first, signed in, even when it is not remembered.
	Current *domain.Session
}

// LogoutRequest ends a session at the user's request, and records it in the
// audit log.
type LogoutRequest struct {
	SessionID string
	Via       domain.LogoutVia
	ClientID  string // client_id (OIDC) or entity ID (SAML) that asked, if any
	IPAddress string
	UserAgent string
	// Confirmed: the user answered "Sign out" on the confirmation page.
	Confirmed bool
}

// IssuedSession is returned once, at session creation.
//
// RawToken only exists in memory: the database stores its hash. The caller
// must put it in the session cookie right away; it can never be recovered.
type IssuedSession struct {
	RawToken string
	Session  *domain.Session
}

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

	// Entitlements: the user's effective permissions on this client,
	// "resource:action", sorted. Computed ONLY for the internal admin client
	// (domain.InternalAdminClientID, the admin console), nil for every other
	// client. The OIDC adapter puts them in the access token's
	// "entitlements" claim (RFC 9068, section 2.2.3.1), so the Admin API
	// authorizes a call without reading the database.
	Entitlements []string
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

type DigestSigner interface {
	Signer
	// SignDigest signs a 32-byte SHA-256 digest (RSA PKCS#1 v1.5 for RSA).
	SignDigest(ctx context.Context, digest []byte) ([]byte, error)
	// CertificatePEM is the X.509 certificate of the key, PEM encoded
	// (saml_signing keys). Empty when the key has none (jwt_signing).
	CertificatePEM() string
}

type SessionParticipant struct {
	SessionID string
	ClientRef string // ClientApp.ID
	// Subject / SubjectFormat are what the client received (SAML NameID and
	// its Format URI): a logout message must repeat them exactly.
	Subject       string
	SubjectFormat string
}


type ConsentItem struct {
	Scope       string // stored in Consent.scopes, e.g. "email" or "saml_profile"
	Title       string // plain language, e.g. "Your e-mail address"
	Description string // optional detail under the title
}

// ConsentCheck asks "must this user approve these scopes for this client
// before going on?". It is the isolated, composable step the plan calls
// shouldRequestConsent: today the adapters call it right after the identity
// assertion, a future per-client authentication flow can call it anywhere.
type ConsentCheck struct {
	SessionID string // the session proves who the user is
	ClientRef string // ClientApp.ID
	// Scopes the client is about to receive (names of ConsentItem.Scope).
	// Empty is valid: the client still learns who the user is.
	Scopes []string
	// Force asks for the screen even when the client does not require
	// consent or the user already approved everything (OIDC prompt=consent).
	Force bool
}

// ConsentDecision is the answer of CheckConsent.
type ConsentDecision struct {
	// Required: show the consent screen before issuing anything.
	Required bool
	// Missing are the requested scopes the user has not approved yet, in
	// request order. Missing can be empty while Required is true: first use
	// of a client that only asks for the user's identity, or Force.
	Missing []string
	// Previously is true when the user had approved this client before
	// (some scopes): the screen can say "asks for more than before".
	Previously bool
}

// ConsentGrant records what the user approved on the consent screen.
type ConsentGrant struct {
	SessionID string
	ClientRef string
	// Items exactly as shown to the user. Their Scope names are stored;
	// their Titles go into the "an application can access your account"
	// e-mail.
	Items     []ConsentItem
	IPAddress string
	UserAgent string
}

// ConsentDenial records that the user refused (AuditLog only: nothing is
// stored, the next request asks again).
type ConsentDenial struct {
	SessionID string
	ClientRef string
	Scopes    []string
	IPAddress string
	UserAgent string
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
	// SessionOptions tells the sign-in page what it may offer in a realm.
	SessionOptions(ctx context.Context, realmID string) SessionOptions
	// Logout ends a session the user asked to leave and writes the audit
	// entry. A session that is already over is not an error.
	Logout(ctx context.Context, req LogoutRequest) error

	// --- "Pick an account" ---

	// KnownAccounts returns the accounts to show on a device: the current
	// session's first, then the remembered ones, most recently used first.
	// Disabled or deleted accounts are never shown.
	KnownAccounts(ctx context.Context, q AccountQuery) ([]Account, error)
	// SessionAccount describes the account of an active session (ID empty,
	// SignedIn false). ErrSessionInvalid if the session is over.
	SessionAccount(ctx context.Context, sessionID string) (*Account, error)

	// --- Identity assertions (format-agnostic) ---

	// IssueIdentityAssertion checks the session, the user's right to access
	// the client, active timeouts and the MFA policy (*MFARequiredError),
	// then builds the neutral assertion.
	// An empty requestedScopes means "all effective scopes".
	IssueIdentityAssertion(ctx context.Context, sessionID, clientRef string, requestedScopes []string) (*IdentityAssertion, error)


	CheckConsent(ctx context.Context, c ConsentCheck) (*ConsentDecision, error)
	// GrantConsent stores the approval for the session's user: the new
	// scopes are merged with those approved before (one Consent row per user
	// and client). A revoked consent starts again from these items only.
	GrantConsent(ctx context.Context, g ConsentGrant) (*domain.Consent, error)
	// DenyConsent records a refusal in the AuditLog.
	DenyConsent(ctx context.Context, d ConsentDenial) error

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


	RegisterSessionParticipant(ctx context.Context, p SessionParticipant) (*domain.Token, error)
	// SessionParticipants returns the participant records of a session that
	// are not revoked yet, oldest first. Call it BEFORE RevokeSession, which
	// revokes them.
	SessionParticipants(ctx context.Context, sessionID string) ([]*domain.Token, error)


	LookupClient(ctx context.Context, realmID string, protocol domain.ClientAppProtocol, protocolID string) (*ProtocolClient, error)
	ClientByRef(ctx context.Context, clientRef string) (*ProtocolClient, error)
	// AuthenticateClient checks the secret of a confidential client, in
	// constant time. Wrong secret, or a client without a secret (public):
	// ErrInvalidClientSecret.
	AuthenticateClient(ctx context.Context, clientRef, secret string) error

	// --- Keys ---

	// Signer returns the newest active key of the realm for that purpose.
	// For saml_signing it is also a DigestSigner.
	Signer(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) (Signer, error)
	PublicKeys(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) ([]*domain.SigningKey, error)
}
