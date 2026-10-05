package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	tokens   repository.TokenRepository
	keys     repository.SigningKeyRepository
	km       keymanager.KeyManager
	timeouts TimeoutChecker
	now      func() time.Time
}

// IdentityCoreDeps groups the dependencies. A struct with named fields is
// easier to read (and harder to get wrong) than 9 positional arguments.
type IdentityCoreDeps struct {
	Auth        *AuthService
	Sessions    *SessionService
	RBAC        *RBACService
	Users       repository.UserRepository
	Clients     repository.ClientRepository
	Tokens      repository.TokenRepository
	SigningKeys repository.SigningKeyRepository
	KeyManager  keymanager.KeyManager
	// Timeouts should be the same checker given to AuthService. nil means
	// NoActiveTimeouts.
	Timeouts TimeoutChecker
}

type IdentityCoreOption func(*IdentityCoreService)

// WithIdentityCoreClock injects a fake clock (tests).
func WithIdentityCoreClock(now func() time.Time) IdentityCoreOption {
	return func(s *IdentityCoreService) { s.now = now }
}

func NewIdentityCore(d IdentityCoreDeps, opts ...IdentityCoreOption) *IdentityCoreService {
	s := &IdentityCoreService{
		auth:     d.Auth,
		sessions: d.Sessions,
		rbac:     d.RBAC,
		users:    d.Users,
		clients:  d.Clients,
		tokens:   d.Tokens,
		keys:     d.SigningKeys,
		km:       d.KeyManager,
		timeouts: d.Timeouts,
		now:      time.Now,
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

func (s *IdentityCoreService) VerifyMFA(context.Context, string, core.MFAChallenge) (bool, error) {
	return false, core.ErrMFANotImplemented
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
		Subject:     user.ID,
		Audience:    audience,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		AuthTime:    sess.CreatedAt,
		AuthMethod:  sess.AuthMethod,
		MFAVerified: sess.MFAVerified,
		SessionID:   sess.ID,
		ClientRef:   client.ID,
		Claims:      userClaims(user),
		Scopes:      scopes,
	}, nil
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

// filterRequestedScopes keeps the effective scopes whose name was requested.
// An empty request means "everything the user is entitled to". A requested
// scope the user does not have is silently dropped: requesting never grants.
func filterRequestedScopes(effective []*domain.ClientScope, requested []string) []*domain.ClientScope {
	if len(requested) == 0 {
		return effective
	}
	out := make([]*domain.ClientScope, 0, len(effective))
	for _, cs := range effective {
		if slices.Contains(requested, cs.Name) {
			out = append(out, cs)
		}
	}
	return out
}

func userClaims(u *domain.User) map[string]any {
	claims := map[string]any{"username": u.Username}
	if u.Email != "" {
		claims["email"] = u.Email
	}
	return claims
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
