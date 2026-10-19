package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
	"sso.internal/sso/internal/keymanager"
)

// defaultAssertionTTL is used when the client has no usable id_token_ttl
// (and always for SAML, where assertions are meant to be short-lived).
const defaultAssertionTTL = 5 * time.Minute

// Compile-time check: the build fails if a method of core.IdentityCore is
// missing or has the wrong signature.
var _ core.IdentityCore = (*IdentityCoreService)(nil)

// IdentityCoreService implements core.IdentityCore by orchestrating the
// services built in Steps 4 to 6 plus a few repositories and the KeyManager.
// It contains no HTTP, no Ent, no JWT and no XML.
type IdentityCoreService struct {
	auth     *AuthService
	sessions *SessionService
	rbac     *RBACService
	users    repository.UserRepository
	clients  repository.ClientRepository
	realms   repository.RealmRepository
	tokens   repository.TokenRepository
	keys     repository.SigningKeyRepository
	km       keymanager.KeyManager
	timeouts TimeoutChecker
	mfa      *MFAService                   // nil: MFA not configured (no policy enforced)
	audit    repository.AuditLogRepository // nil: refresh token replays are only logged
	logger   *slog.Logger
	now      func() time.Time

	// Pairwise salts never change once written, so they are cached forever.
	saltMu sync.Mutex
	salts  map[string]string // realmID -> salt
}

// IdentityCoreDeps groups the dependencies. A struct with named fields is
// easier to read (and harder to get wrong) than 9 positional arguments.
type IdentityCoreDeps struct {
	Auth        *AuthService
	Sessions    *SessionService
	RBAC        *RBACService
	Users       repository.UserRepository
	Clients     repository.ClientRepository
	Realms      repository.RealmRepository // pairwise subject salt
	Tokens      repository.TokenRepository
	SigningKeys repository.SigningKeyRepository
	KeyManager  keymanager.KeyManager
	// Timeouts should be the same checker given to AuthService. nil means
	// NoActiveTimeouts.
	Timeouts TimeoutChecker
	// MFA enforces the MFA policies in IssueIdentityAssertion and backs
	// VerifyMFA (Step 9). nil: no MFA (tests of earlier steps).
	MFA *MFAService
	// Audit records refresh token replays (Step 10). nil: logged only.
	Audit repository.AuditLogRepository
}

type IdentityCoreOption func(*IdentityCoreService)

// WithIdentityCoreClock injects a fake clock (tests).
func WithIdentityCoreClock(now func() time.Time) IdentityCoreOption {
	return func(s *IdentityCoreService) { s.now = now }
}

// WithIdentityCoreLogger sets the logger (default: slog.Default()).
func WithIdentityCoreLogger(l *slog.Logger) IdentityCoreOption {
	return func(s *IdentityCoreService) { s.logger = l }
}

func NewIdentityCore(d IdentityCoreDeps, opts ...IdentityCoreOption) *IdentityCoreService {
	s := &IdentityCoreService{
		auth:     d.Auth,
		sessions: d.Sessions,
		rbac:     d.RBAC,
		users:    d.Users,
		clients:  d.Clients,
		realms:   d.Realms,
		tokens:   d.Tokens,
		keys:     d.SigningKeys,
		km:       d.KeyManager,
		timeouts: d.Timeouts,
		mfa:      d.MFA,
		audit:    d.Audit,
		logger:   slog.Default(),
		now:      time.Now,
		salts:    make(map[string]string),
	}
	if s.timeouts == nil {
		s.timeouts = NoActiveTimeouts{}
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// --- Authentication ---------------------------------------------------------

func (s *IdentityCoreService) AuthenticateLocal(ctx context.Context, c core.Credentials) (*domain.User, error) {
	return s.auth.AuthenticateLocal(ctx, AuthenticateLocalParams{
		RealmID:    c.RealmID,
		Identifier: c.Identifier,
		Password:   c.Password,
		IPAddress:  c.IPAddress,
		UserAgent:  c.UserAgent,
		ClientRef:  c.ClientRef,
	})
}

func (s *IdentityCoreService) VerifyMFA(ctx context.Context, userID string, ch core.MFAChallenge) (bool, error) {
	if s.mfa == nil {
		return false, core.ErrMFANotImplemented
	}
	_, ok, err := s.mfa.VerifyCode(ctx, userID, ch.Method, ch.Response)
	return ok, err
}

// --- Sessions ---------------------------------------------------------------

func (s *IdentityCoreService) CreateSession(ctx context.Context, userID string, ac core.AuthContext) (*core.IssuedSession, error) {
	raw, sess, err := s.sessions.Create(ctx, CreateSessionInput{
		RealmID:       ac.RealmID,
		UserID:        userID,
		IPAddress:     ac.IPAddress,
		UserAgent:     ac.UserAgent,
		AuthMethod:    ac.AuthMethod,
		MFAVerified:   ac.MFAVerified,
		MFAMethodType: ac.MFAMethodType,
	})
	if err != nil {
		return nil, err
	}
	return &core.IssuedSession{RawToken: raw, Session: sess}, nil
}

func (s *IdentityCoreService) ValidateSession(ctx context.Context, realmID, rawToken string) (*domain.Session, error) {
	return s.sessions.Validate(ctx, realmID, rawToken)
}

func (s *IdentityCoreService) GetSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	return s.sessions.GetActive(ctx, sessionID)
}

func (s *IdentityCoreService) RevokeSession(ctx context.Context, sessionID string, reason domain.SessionRevokedReason) error {
	return s.sessions.Revoke(ctx, sessionID, reason)
}

// --- Identity assertions ----------------------------------------------------

func (s *IdentityCoreService) IssueIdentityAssertion(ctx context.Context, sessionID, clientRef string, requestedScopes []string) (*core.IdentityAssertion, error) {
	// 1. The session must still be valid.
	sess, err := s.sessions.GetActive(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// 2. Authorization BEFORE reading any user data. A denial is written to
	//    the AuditLog by the RBAC service (Step 6).
	if err := s.rbac.AuthorizeClientAccess(ctx, AuthorizeInput{
		RealmID:   sess.RealmID,
		UserID:    sess.UserID,
		ClientRef: clientRef,
		IPAddress: sess.IPAddress,
		UserAgent: sess.UserAgent,
	}); err != nil {
		return nil, err
	}

	// 3. Admin-issued timeouts (no-op until Phase 2).
	blocked, err := s.timeouts.HasActiveTimeout(ctx, sess.UserID, clientRef)
	if err != nil {
		return nil, fmt.Errorf("issue identity assertion: check timeout: %w", err)
	}
	if blocked {
		return nil, core.ErrTimeoutActive
	}

	// 4. Data needed to build the assertion.
	user, err := s.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("issue identity assertion: load user: %w", err)
	}
	client, err := s.clients.GetByID(ctx, clientRef)
	if err != nil {
		return nil, fmt.Errorf("issue identity assertion: load client: %w", err)
	}
	audience, err := audienceFor(client)
	if err != nil {
		return nil, err
	}

	// 4b. MFA policies of the realm, the client and the user's roles
	//     (Step 9). On failure the adapter sends the user to the step-up
	//     page (same session) or to MFA enrollment: *core.MFARequiredError.
	if s.mfa != nil {
		if err := s.mfa.CheckClientAccess(ctx, sess, user, client); err != nil {
			return nil, err
		}
	}

	subject, err := s.subjectFor(ctx, user, client)
	if err != nil {
		return nil, err
	}

	// Names of the user's groups and roles: claim sources ("groups" scope),
	// never emitted unless a claim mapper asks for them.
	groups, roles, err := s.rbac.UserAccessNames(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("issue identity assertion: user groups and roles: %w", err)
	}

	// 5. Effective scopes, narrowed to what the client asked for.
	//    (This resolves RBAC a second time; fine for now, can be merged
	//    into a single call later if it shows up in profiling.)
	scopes, err := s.rbac.GetEffectiveClientScopes(ctx, sess.UserID, clientRef)
	if err != nil {
		return nil, fmt.Errorf("issue identity assertion: effective scopes: %w", err)
	}
	scopes = filterRequestedScopes(scopes, requestedScopes)

	// 6. Lifetime: client TTL, but never beyond the session itself.
	now := s.now()
	expiresAt := now.Add(assertionTTL(client))
	if sess.ExpiresAt.Before(expiresAt) {
		expiresAt = sess.ExpiresAt
	}

	// 7. Build the neutral object.
	return &core.IdentityAssertion{
		Subject:        subject,
		Audience:       audience,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		AuthTime:       sess.CreatedAt,
		AuthMethods:    authMethodRefs(sess),
		MFAVerified:    sess.MFAVerified,
		SessionID:      sess.ID,
		ClientRef:      client.ID,
		UserID:         user.ID,
		UserAttributes: userAttributes(user, groups, roles),
		Scopes:         scopes,
	}, nil
}

// subjectFor returns the identifier this client will see for this user.
func (s *IdentityCoreService) subjectFor(ctx context.Context, u *domain.User, c *domain.ClientApp) (string, error) {
	switch c.SubjectType {
	case domain.ClientAppSubjectPublic, "":
		return u.ID, nil
	case domain.ClientAppSubjectPairwise:
		salt, err := s.pairwiseSalt(ctx, c.RealmID)
		if err != nil {
			return "", err
		}
		sector := c.SectorIdentifier
		if sector == "" {
			sector = c.ID
		}
		return pairwiseSubject(salt, sector, u.ID), nil
	default:
		// Fail closed: never guess which identifier an unknown type means.
		return "", fmt.Errorf("%w: client %s has unknown subject_type %q", core.ErrClientMisconfigured, c.ID, c.SubjectType)
	}
}

// pairwiseSubject derives a stable, non-correlatable identifier
// (OIDC Core §8.1): HMAC-SHA256 keyed with the realm salt, over the sector
// and the user id. The 0x00 separator keeps ("ab","c") and ("a","bc")
// distinct. Without the salt, nobody can link two sectors' subjects.
func pairwiseSubject(salt, sector, userID string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(sector))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) // 43 chars
}

// pairwiseSalt returns the realm salt, creating it on first use.
func (s *IdentityCoreService) pairwiseSalt(ctx context.Context, realmID string) (string, error) {
	s.saltMu.Lock()
	salt, ok := s.salts[realmID]
	s.saltMu.Unlock()
	if ok {
		return salt, nil
	}

	// If two processes race, the repository keeps the first value written
	// and both get it back: everyone ends up with the same salt.
	salt, err := s.realms.EnsurePairwiseSubjectSalt(ctx, realmID, rand.Text())
	if err != nil {
		return "", fmt.Errorf("pairwise subject salt: %w", err)
	}
	if salt == "" {
		return "", fmt.Errorf("pairwise subject salt: empty salt for realm %s", realmID)
	}

	s.saltMu.Lock()
	s.salts[realmID] = salt
	s.saltMu.Unlock()
	return salt, nil
}

// authMethodRefs builds the RFC 8176 list for the "amr" claim.
func authMethodRefs(sess *domain.Session) []string {
	amr := make([]string, 0, 3)
	add := func(v string) {
		if v != "" && !slices.Contains(amr, v) {
			amr = append(amr, v)
		}
	}
	add(sess.AuthMethod)
	if sess.MFAVerified {
		add(mfaMethodRef(domain.MfaMethodType(sess.MFAMethodType)))
		add(domain.AuthMethodMFA)
	}
	return amr
}

// mfaMethodRef maps an MFA method to its RFC 8176 value. RFC 8176 has no
// "passkey" value: a passkey is a proof of possession of a key protected by
// the device ("hwk"), like a security key. Biometrics are not a separate
// factor here (Face ID only unlocks the passkey). "mfa" is always added.
func mfaMethodRef(t domain.MfaMethodType) string {
	switch t {
	case domain.MfaMethodTOTP, domain.MfaMethodBackupCodes:
		return domain.AuthMethodOTP
	case domain.MfaMethodWebAuthn, domain.MfaMethodPasskey:
		return domain.AuthMethodHardwareKey
	default:
		return ""
	}
}

func audienceFor(c *domain.ClientApp) (string, error) {
	var aud string
	switch c.Protocol {
	case domain.ClientAppProtocolOIDC:
		aud = c.ClientID
	case domain.ClientAppProtocolSAML2:
		aud = c.EntityID
	}
	if aud == "" {
		return "", fmt.Errorf("%w: client %s (%s) has no audience identifier", core.ErrClientMisconfigured, c.ID, c.Protocol)
	}
	return aud, nil
}

func assertionTTL(c *domain.ClientApp) time.Duration {
	if c.Protocol == domain.ClientAppProtocolOIDC && c.IDTokenTTL > 0 {
		return time.Duration(c.IDTokenTTL) * time.Second // id_token_ttl is in seconds
	}
	return defaultAssertionTTL
}

// filterRequestedScopes keeps the effective scopes whose name was requested,
// plus the "is_default" ones, which are included without being asked for.
// An empty request means "everything the user is entitled to". A requested
// scope the user does not have is silently dropped: requesting never grants,
// and is_default never grants either (the scope must be effective first).
func filterRequestedScopes(effective []*domain.ClientScope, requested []string) []*domain.ClientScope {
	if len(requested) == 0 {
		return effective
	}
	out := make([]*domain.ClientScope, 0, len(effective))
	for _, cs := range effective {
		if cs.IsDefault || slices.Contains(requested, cs.Name) {
			out = append(out, cs)
		}
	}
	return out
}

// userAttributes lists what claim mappers may read. See
// core.IdentityAssertion.UserAttributes for the keys.
func userAttributes(u *domain.User, groups, roles []string) map[string]any {
	attrs := map[string]any{"username": u.Username}
	if u.Email != "" {
		attrs["email"] = u.Email
	}
	if !u.UpdatedAt.IsZero() {
		attrs["updated_at"] = u.UpdatedAt.Unix()
	}
	for k, v := range u.Profile {
		attrs["profile."+k] = v
	}
	if groups == nil {
		groups = []string{}
	}
	if roles == nil {
		roles = []string{}
	}
	attrs["groups"] = groups
	attrs["roles"] = roles
	return attrs
}

// --- Authorization ----------------------------------------------------------

func (s *IdentityCoreService) GetEffectivePermissions(ctx context.Context, userID, clientRef string) ([]*domain.Permission, error) {
	return s.rbac.GetEffectivePermissions(ctx, userID, clientRef)
}

func (s *IdentityCoreService) IsAuthorizedForClient(ctx context.Context, userID, clientRef string) (bool, error) {
	ok, err := s.rbac.CanAccessClient(ctx, userID, clientRef)
	if err != nil || !ok {
		return false, err
	}
	blocked, err := s.timeouts.HasActiveTimeout(ctx, userID, clientRef)
	if err != nil {
		return false, fmt.Errorf("is authorized for client: check timeout: %w", err)
	}
	return !blocked, nil
}

// --- Tokens -----------------------------------------------------------------

func (s *IdentityCoreService) RevokeToken(ctx context.Context, jti string) error {
	tok, err := s.tokens.GetByJTI(ctx, jti)
	if errors.Is(err, repository.ErrNotFound) {
		return nil // idempotent: nothing to revoke
	}
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	if tok.Revoked {
		return nil
	}
	if err := s.tokens.Revoke(ctx, tok.ID); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

func (s *IdentityCoreService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	tok, err := s.tokens.GetByJTI(ctx, jti)
	if errors.Is(err, repository.ErrNotFound) {
		return true, nil // fail closed: we never issued it, so we don't trust it
	}
	if err != nil {
		return true, fmt.Errorf("is token revoked: %w", err)
	}
	return tok.Revoked, nil
}

// --- Keys -------------------------------------------------------------------

func (s *IdentityCoreService) Signer(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) (core.Signer, error) {
	keys, err := s.keys.ListActiveByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("signer: list keys: %w", err)
	}

	var best *domain.SigningKey
	for _, k := range keys {
		// ListActiveByRealm also returns "rotating" keys: they stay valid for
		// verification (JWKS) but must not sign anything new.
		if k.Purpose != purpose || k.Status != domain.SigningKeyActive {
			continue
		}
		if best == nil || k.CreatedAt.After(best.CreatedAt) {
			best = k
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: realm %s, purpose %s", core.ErrNoActiveSigningKey, realmID, purpose)
	}
	return &kmsSigner{km: s.km, key: best}, nil
}

func (s *IdentityCoreService) PublicKeys(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) ([]*domain.SigningKey, error) {
	keys, err := s.keys.ListActiveByRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("public keys: list keys: %w", err)
	}
	return VerificationKeys(keys, purpose, s.now()), nil
}

// VerificationKeys keeps the keys that may still verify a signature at now,
// newest first.
//
// A "rotating" key is dropped as soon as its grace deadline has passed, even
// if the retire job has not run yet: the deadline decides what is published,
// the job only tidies the status and writes the KeyRotationLog. So the grace
// period is enforced even without a cron.
func VerificationKeys(keys []*domain.SigningKey, purpose domain.SigningKeyPurpose, now time.Time) []*domain.SigningKey {
	out := make([]*domain.SigningKey, 0, len(keys))
	for _, k := range keys {
		if k.Purpose != purpose {
			continue
		}
		switch k.Status {
		case domain.SigningKeyActive, domain.SigningKeyPending:
			// pending (Step 11, SAML): published before it signs, so that
			// clients which copy the certificate by hand can add it first.
			out = append(out, k)
		case domain.SigningKeyRotating:
			// A zero RetireAfter only exists on rows created before the
			// deadline column: keep them, the migration gave them one.
			if k.RetireAfter.IsZero() || now.Before(k.RetireAfter) {
				out = append(out, k)
			}
		}
	}
	// Newest first: a stable order gives a stable JWKS body (and ETag), and
	// some naive clients simply take the first key.
	slices.SortStableFunc(out, func(a, b *domain.SigningKey) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return out
}

// kmsSigner binds one SigningKey row to the KeyManager. The private key never
// leaves the KMS: we only pass its reference.
type kmsSigner struct {
	km  keymanager.KeyManager
	key *domain.SigningKey
}

func (k *kmsSigner) KeyID() string                  { return k.key.Kid }
func (k *kmsSigner) KeyType() domain.SigningKeyType { return k.key.KeyType }

func (k *kmsSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	sig, err := k.km.Sign(ctx, k.key.KMSKeyReference, payload)
	if err != nil {
		return nil, fmt.Errorf("sign with key %s: %w", k.key.Kid, err)
	}
	return sig, nil
}

// kmsSigner is also a core.DigestSigner (Step 11, XML-DSig).
var _ core.DigestSigner = (*kmsSigner)(nil)

func (k *kmsSigner) SignDigest(ctx context.Context, digest []byte) ([]byte, error) {
	ds, ok := k.km.(keymanager.DigestSigner)
	if !ok {
		return nil, fmt.Errorf("sign digest with key %s: %w", k.key.Kid, ErrDigestSigningUnsupported)
	}
	sig, err := ds.SignDigest(ctx, k.key.KMSKeyReference, digest)
	if err != nil {
		return nil, fmt.Errorf("sign digest with key %s: %w", k.key.Kid, err)
	}
	return sig, nil
}

func (k *kmsSigner) CertificatePEM() string { return k.key.Certificate }
