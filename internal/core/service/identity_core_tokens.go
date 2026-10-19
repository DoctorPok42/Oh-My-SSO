package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Token primitives for the protocol adapters (Step 10). Format-agnostic: the
// core records which tokens exist and how long they live; the OIDC adapter
// turns the records into JWTs.

const (
	// Used when the client row has no usable value.
	defaultAccessTokenTTL  = 5 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour

	auditActionRefreshTokenReuse = "refresh_token_reuse_detected"
)

// --- Protocol clients -------------------------------------------------------

func (s *IdentityCoreService) LookupClient(ctx context.Context, realmID string, protocol domain.ClientAppProtocol, protocolID string) (*core.ProtocolClient, error) {
	if realmID == "" || protocolID == "" {
		return nil, core.ErrClientNotFound
	}
	var (
		app *domain.ClientApp
		err error
	)
	switch protocol {
	case domain.ClientAppProtocolOIDC:
		app, err = s.clients.GetByRealmAndClientID(ctx, realmID, protocolID)
	case domain.ClientAppProtocolSAML2:
		app, err = s.clients.GetByRealmAndEntityID(ctx, realmID, protocolID)
	default:
		return nil, core.ErrClientNotFound
	}
	if errors.Is(err, repository.ErrNotFound) {
		return nil, core.ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup client: %w", err)
	}
	if app.IsDeleted() || app.Status != domain.ClientAppActive || app.Protocol != protocol || app.RealmID != realmID {
		return nil, core.ErrClientNotFound
	}
	scopes, err := s.clients.ListScopes(ctx, app.ID)
	if err != nil {
		return nil, fmt.Errorf("lookup client: scopes: %w", err)
	}
	return &core.ProtocolClient{App: app, Scopes: scopes}, nil
}

func (s *IdentityCoreService) ClientByRef(ctx context.Context, clientRef string) (*core.ProtocolClient, error) {
	if clientRef == "" {
		return nil, core.ErrClientNotFound
	}
	app, err := s.clients.GetByID(ctx, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, core.ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client by ref: %w", err)
	}
	if app.IsDeleted() || app.Status != domain.ClientAppActive {
		return nil, core.ErrClientNotFound
	}
	scopes, err := s.clients.ListScopes(ctx, app.ID)
	if err != nil {
		return nil, fmt.Errorf("client by ref: scopes: %w", err)
	}
	return &core.ProtocolClient{App: app, Scopes: scopes}, nil
}

func (s *IdentityCoreService) AuthenticateClient(ctx context.Context, clientRef, secret string) error {
	app, err := s.clients.GetByID(ctx, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return core.ErrInvalidClientSecret
	}
	if err != nil {
		return fmt.Errorf("authenticate client: %w", err)
	}
	if app.IsDeleted() || app.Status != domain.ClientAppActive ||
		app.ClientType == domain.ClientAppTypePublic || !verifyClientSecret(secret, app.ClientSecretHash) {
		return core.ErrInvalidClientSecret
	}
	return nil
}

// --- Tokens -----------------------------------------------------------------

func (s *IdentityCoreService) IssueTokens(ctx context.Context, req core.TokenRequest) (*core.IssuedTokens, error) {
	sess, client, err := s.tokenContext(ctx, req.SessionID, req.ClientRef)
	if err != nil {
		return nil, err
	}
	return s.issueTokens(ctx, sess, client, req.Scopes, uuid.NewString(), req.WithRefreshToken)
}

func (s *IdentityCoreService) InspectRefreshToken(ctx context.Context, rawToken string) (*domain.Token, error) {
	if rawToken == "" {
		return nil, core.ErrTokenInvalid
	}
	tok, err := s.tokens.GetByHash(ctx, HashSessionToken(rawToken))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("inspect refresh token: %w", err)
	}
	if tok.Type != domain.TokenRefreshToken {
		return nil, core.ErrTokenInvalid
	}
	if tok.IsUsed() {
		// Checked before "revoked": after a replay the family is revoked, and
		// a second replay must still be reported (and audited) as one.
		s.refreshTokenReplayed(ctx, tok)
		return nil, core.ErrTokenReused
	}
	if tok.Revoked || !s.now().Before(tok.ExpiresAt) {
		return nil, core.ErrTokenInvalid
	}
	return tok, nil
}

func (s *IdentityCoreService) RotateRefreshToken(ctx context.Context, rawToken, clientRef string, scopes []string) (*core.IssuedTokens, error) {
	old, err := s.InspectRefreshToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	if old.ClientRefID != clientRef {
		// A client presenting another client's token: refuse, but do not
		// consume it (the rightful owner may still use it).
		return nil, core.ErrTokenInvalid
	}
	if scopes == nil {
		scopes = old.Scopes
	} else {
		for _, sc := range scopes {
			if !slices.Contains(old.Scopes, sc) {
				return nil, fmt.Errorf("%w: scope %q was not granted", core.ErrTokenInvalid, sc)
			}
		}
	}

	sess, client, err := s.tokenContext(ctx, old.SessionID, clientRef)
	if err != nil {
		return nil, err
	}

	// The one atomic step: whoever marks the token first owns the rotation.
	won, err := s.tokens.MarkUsed(ctx, old.ID, s.now())
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}
	if !won {
		// Another request exchanged (or revoked) it a moment ago. If it was
		// exchanged, two parties hold the same token: treat it as a replay.
		if cur, err := s.tokens.GetByID(ctx, old.ID); err == nil && cur.IsUsed() {
			s.refreshTokenReplayed(ctx, cur)
			return nil, core.ErrTokenReused
		}
		return nil, core.ErrTokenInvalid
	}

	// Refresh tokens are bound to the SSO session: using one is activity,
	// it keeps the session's idle timer from running out (Keycloak does the
	// same). The session's maximum lifetime still applies.
	if sess, err = s.sessions.TouchActive(ctx, sess.ID); err != nil {
		return nil, err
	}
	issued, err := s.issueTokens(ctx, sess, client, scopes, old.FamilyID, true)
	if err != nil {
		return nil, err
	}
	// Close the race with a concurrent replay: a loser of MarkUsed revokes
	// the family, maybe just BEFORE our new tokens were inserted (so they
	// escaped it). It always revokes the old row too, so check it again.
	if cur, err := s.tokens.GetByID(ctx, old.ID); err != nil || cur.Revoked {
		if _, rerr := s.tokens.RevokeFamily(ctx, old.FamilyID); rerr != nil {
			s.logger.ErrorContext(ctx, "rotate refresh token: could not revoke the family after a replay", "error", rerr)
		}
		return nil, core.ErrTokenReused
	}
	return issued, nil
}

func (s *IdentityCoreService) LookupToken(ctx context.Context, jti string) (*domain.Token, error) {
	if jti == "" {
		return nil, core.ErrTokenInvalid
	}
	tok, err := s.tokens.GetByJTI(ctx, jti)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, core.ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("lookup token: %w", err)
	}
	return tok, nil
}

func (s *IdentityCoreService) RevokeTokenFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	if _, err := s.tokens.RevokeFamily(ctx, familyID); err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}
	return nil
}

// tokenContext loads and checks what every token issuance needs: an active
// session, an active client of the same realm, and a user still allowed to
// use that client (RBAC + timeouts). The MFA policy is checked by
// IssueIdentityAssertion, which adapters call first.
func (s *IdentityCoreService) tokenContext(ctx context.Context, sessionID, clientRef string) (*domain.Session, *domain.ClientApp, error) {
	sess, err := s.sessions.GetActive(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	client, err := s.clients.GetByID(ctx, clientRef)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, core.ErrClientNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("issue tokens: load client: %w", err)
	}
	if client.IsDeleted() || client.Status != domain.ClientAppActive {
		return nil, nil, core.ErrClientNotFound
	}
	if client.RealmID != sess.RealmID {
		return nil, nil, core.ErrForbidden
	}
	ok, err := s.IsAuthorizedForClient(ctx, sess.UserID, client.ID)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, core.ErrForbidden
	}
	return sess, client, nil
}

func (s *IdentityCoreService) issueTokens(ctx context.Context, sess *domain.Session, client *domain.ClientApp,
	scopes []string, familyID string, withRefresh bool) (*core.IssuedTokens, error) {
	now := s.now()
	if scopes == nil {
		scopes = []string{}
	}

	access, err := s.tokens.Create(ctx, repository.CreateTokenParams{
		SessionID:   sess.ID,
		ClientRefID: client.ID,
		Type:        domain.TokenAccessToken,
		JTI:         uuid.NewString(),
		ExpiresAt:   capToSession(now.Add(seconds(client.AccessTokenTTL, defaultAccessTokenTTL)), sess),
		Scopes:      scopes,
		FamilyID:    familyID,
	})
	if err != nil {
		return nil, fmt.Errorf("issue tokens: access token: %w", err)
	}
	out := &core.IssuedTokens{FamilyID: familyID, Access: access}
	if !withRefresh {
		return out, nil
	}

	// 2 x 130 random bits, base32. Only the hash is stored.
	raw := rand.Text() + rand.Text()
	refresh, err := s.tokens.Create(ctx, repository.CreateTokenParams{
		SessionID:   sess.ID,
		ClientRefID: client.ID,
		Type:        domain.TokenRefreshToken,
		JTI:         uuid.NewString(),
		ExpiresAt:   capToSession(now.Add(seconds(client.RefreshTokenTTL, defaultRefreshTokenTTL)), sess),
		Scopes:      scopes,
		TokenHash:   HashSessionToken(raw),
		FamilyID:    familyID,
	})
	if err != nil {
		return nil, fmt.Errorf("issue tokens: refresh token: %w", err)
	}
	out.RefreshToken, out.Refresh = raw, refresh
	return out, nil
}

// refreshTokenReplayed revokes the family and leaves a trace. A replay means
// the token leaked: the legitimate app and the thief both lose their tokens
// and the user has to log in again (RFC 9700, section 4.14.2).
func (s *IdentityCoreService) refreshTokenReplayed(ctx context.Context, tok *domain.Token) {
	revoked := 0
	var err error
	if tok.FamilyID != "" {
		revoked, err = s.tokens.RevokeFamily(ctx, tok.FamilyID)
	} else {
		err = s.tokens.Revoke(ctx, tok.ID)
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		s.logger.ErrorContext(ctx, "refresh token replay: could not revoke the token family",
			"family_id", tok.FamilyID, "error", err)
	}
	s.logger.WarnContext(ctx, "refresh token replay detected, token family revoked",
		"family_id", tok.FamilyID, "client_ref", tok.ClientRefID, "session_id", tok.SessionID, "revoked", revoked)

	if s.audit == nil {
		return
	}
	entry := repository.CreateAuditLogParams{
		Action:       auditActionRefreshTokenReuse,
		ResourceType: "Token",
		ResourceID:   tok.FamilyID,
		Level:        domain.AuditLogWarning,
		Status:       domain.AuditLogFailure,
		Details: map[string]interface{}{
			"client_ref":     tok.ClientRefID,
			"session_id":     tok.SessionID,
			"token_jti":      tok.JTI,
			"tokens_revoked": revoked,
		},
	}
	// The session row outlives its revocation: it tells whose token it was.
	if sess, err := s.sessions.sessions.GetByID(ctx, tok.SessionID); err == nil {
		entry.RealmID, entry.UserID = sess.RealmID, sess.UserID
	} else if c, err := s.clients.GetByID(ctx, tok.ClientRefID); err == nil {
		entry.RealmID = c.RealmID
	}
	if _, err := s.audit.Create(ctx, entry); err != nil {
		s.logger.ErrorContext(ctx, "refresh token replay: could not write the audit log", "error", err)
	}
}

func seconds(v int, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return time.Duration(v) * time.Second
}

// capToSession: no token outlives the SSO session it was issued for.
func capToSession(t time.Time, sess *domain.Session) time.Time {
	if sess.ExpiresAt.Before(t) {
		return sess.ExpiresAt
	}
	return t
}
