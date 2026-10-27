package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// storage implements op.Storage: it is the bridge between the library and
// the IdP core. Every method only calls core.IdentityCore (users, sessions,
// RBAC, tokens, keys) or oidcstore (short-lived login state).
type storage struct {
	a *Adapter
}

var (
	_ op.Storage                        = (*storage)(nil)
	_ op.CanSetUserinfoFromRequest      = (*storage)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*storage)(nil)
	_ op.CanTerminateSessionFromRequest = (*storage)(nil)
)

func (s *storage) realm(ctx context.Context) (Realm, error) {
	r, ok := realmFrom(ctx)
	if !ok {
		return Realm{}, errors.New("oidc: no realm in the request context")
	}
	return r, nil
}

func (s *storage) lookupClient(ctx context.Context, clientID string) (*core.ProtocolClient, error) {
	realm, err := s.realm(ctx)
	if err != nil {
		return nil, err
	}
	return s.a.core.LookupClient(ctx, realm.ID, protocolOIDC, clientID)
}

// --- clients -------------------------------------------------------------------

func (s *storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	pc, err := s.lookupClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	realm, _ := realmFrom(ctx)
	return &client{pc: pc, loginURL: s.a.issuer(realm.Name) + "/oidc/login?id="}, nil
}

func (s *storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	pc, err := s.lookupClient(ctx, clientID)
	if err != nil {
		return oidc.ErrInvalidClient()
	}
	if err := s.a.core.AuthenticateClient(ctx, pc.App.ID, clientSecret); err != nil {
		if errors.Is(err, core.ErrInvalidClientSecret) {
			return oidc.ErrInvalidClient()
		}
		return err
	}
	return nil
}

// --- authorization requests ------------------------------------------------------

// CreateAuthRequest runs after the library validated the client, the
// redirect_uri and the response_type. It adds this IdP's own rules, then
// stores the request until the login page completes it.
func (s *storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	realm, err := s.realm(ctx)
	if err != nil {
		return nil, err
	}
	pc, err := s.a.core.LookupClient(ctx, realm.ID, protocolOIDC, req.ClientID)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("unknown client")
	}
	browserHash, ok := browserHashFrom(ctx)
	if !ok {
		return nil, errors.New("oidc: browser binding missing (route not wrapped by bindBrowser)")
	}
	if err := checkAuthorizePolicy(pc, req); err != nil {
		return nil, err
	}

	ar := &authRequest{
		ID:                  rand.Text(),
		RealmID:             realm.ID,
		ClientID:            pc.App.ClientID,
		ClientRef:           pc.App.ID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		Scopes:              grantedScopes(pc, req.Scopes),
		ResponseType:        string(req.ResponseType),
		ResponseMode:        string(req.ResponseMode),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		Prompt:              req.Prompt,
		MaxAge:              req.MaxAge,
		LoginHint:           req.LoginHint,
		BrowserHash:         browserHash,
		CreatedAt:           s.a.now(),
	}
	if err := s.a.saveAuthRequest(ctx, ar); err != nil {
		return nil, err
	}
	return ar, nil
}

// checkAuthorizePolicy: rules on top of what the library already checked.
// Every failure is an *oidc.Error, so the user is sent back to the
// application with a precise error (RFC 6749, section 4.1.2.1).
func checkAuthorizePolicy(pc *core.ProtocolClient, req *oidc.AuthRequest) error {
	if !slices.Contains(req.Scopes, scopeOpenID) {
		return oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	// PKCE (RFC 7636): mandatory for public clients, and for confidential
	// ones unless the admin turned require_pkce off. Only S256: "plain"
	// sends the secret itself in the browser (RFC 9700, section 2.1.1).
	if (isPublic(pc.App) || pc.App.RequirePKCE) && req.CodeChallenge == "" {
		return oidc.ErrInvalidRequest().WithDescription("code_challenge is required (PKCE with S256)")
	}
	if req.CodeChallenge != "" && req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}
	switch req.ResponseMode {
	case "", oidc.ResponseModeQuery, oidc.ResponseModeFormPost:
	default:
		return oidc.ErrInvalidRequest().WithDescription("unsupported response_mode")
	}
	return nil
}

// grantedScopes keeps the requested scopes this client may have, in request
// order. Others are dropped silently: the client sees what it got in the
// token response "scope" (RFC 6749, section 3.3).
func grantedScopes(pc *core.ProtocolClient, requested []string) []string {
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if allowsScope(pc, sc) && !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out
}

func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.a.loadAuthRequest(ctx, id)
}

// SaveAuthCode is called by the callback, once per authorization request:
// a second call (replayed callback URL) is refused, so one login gives one
// code.
func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	ar, err := s.a.loadAuthRequest(ctx, id)
	if err != nil {
		return err
	}
	if !ar.Authenticated {
		return oidc.ErrInteractionRequired()
	}
	h := sha256Hex(code)
	first, err := s.a.store.PutIfAbsent(ctx, authRequestCodeKey(id), []byte(h), authRequestTTL)
	if err != nil {
		return err
	}
	if !first {
		return oidc.ErrInvalidRequest().WithDescription("a code was already issued for this login")
	}
	ar.CodeHash = h
	if err := s.a.saveAuthRequest(ctx, ar); err != nil {
		return err
	}
	return s.a.store.Put(ctx, codeKey(h), []byte(id), codeTTL)
}

// AuthRequestByCode consumes the code: Take is atomic, so a code works at
// most once even when two requests race. A code that comes back after a
// successful exchange revokes the tokens it gave (RFC 6749, section 4.1.2).
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	h := sha256Hex(code)
	if family, err := s.a.store.Get(ctx, usedCodeKey(h)); err == nil && family != nil {
		if err := s.a.core.RevokeTokenFamily(ctx, string(family)); err != nil {
			s.a.logger.ErrorContext(ctx, "oidc: code replay: could not revoke tokens", "error", err)
		}
		s.a.logger.WarnContext(ctx, "oidc: authorization code used twice, its tokens were revoked", "family_id", string(family))
		return nil, oidc.ErrInvalidGrant().WithDescription("code already used")
	}
	id, err := s.a.store.Take(ctx, codeKey(h))
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid or expired code")
	}
	ar, err := s.a.loadAuthRequest(ctx, string(id))
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid or expired code")
	}
	if !ar.Authenticated || ar.CodeHash != h {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid or expired code")
	}
	return ar, nil
}

func (s *storage) DeleteAuthRequest(ctx context.Context, id string) error {
	if err := s.a.store.Delete(ctx, authRequestKey(id)); err != nil {
		return err
	}
	return s.a.store.Delete(ctx, authRequestCodeKey(id))
}

// --- tokens ----------------------------------------------------------------------

func (s *storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	ar, ok := request.(*authRequest)
	if !ok {
		return "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
	issued, err := s.issueForCode(ctx, ar, false)
	if err != nil {
		return "", time.Time{}, err
	}
	return issued.Access.JTI, issued.Access.ExpiresAt, nil
}

func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	switch req := request.(type) {
	case *authRequest:
		issued, err := s.issueForCode(ctx, req, true)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return issued.Access.JTI, issued.RefreshToken, issued.Access.ExpiresAt, nil
	case *refreshRequest:
		issued, err := s.a.core.RotateRefreshToken(ctx, currentRefreshToken, req.clientRef, req.scopes)
		if err != nil {
			return "", "", time.Time{}, toTokenError(err)
		}
		return issued.Access.JTI, issued.RefreshToken, issued.Access.ExpiresAt, nil
	default:
		return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
}

// issueForCode: the assertion is computed FIRST (RBAC, timeouts, MFA are
// checked again), so no token is recorded for a user who is not allowed.
func (s *storage) issueForCode(ctx context.Context, ar *authRequest, withRefresh bool) (*core.IssuedTokens, error) {
	if _, _, err := s.a.assertionFor(ctx, ar); err != nil {
		return nil, err
	}
	issued, err := s.a.core.IssueTokens(ctx, core.TokenRequest{
		SessionID:        ar.SessionID,
		ClientRef:        ar.ClientRef,
		Scopes:           ar.Scopes,
		WithRefreshToken: withRefresh,
	})
	if err != nil {
		return nil, toTokenError(err)
	}
	// Remember which tokens this code gave, for the code replay check.
	if ar.CodeHash != "" {
		if err := s.a.store.Put(ctx, usedCodeKey(ar.CodeHash), []byte(issued.FamilyID), authRequestTTL); err != nil {
			s.a.logger.WarnContext(ctx, "oidc: could not record the used code", "error", err)
		}
	}
	return issued, nil
}

// TokenRequestByRefreshToken validates a refresh token WITHOUT consuming it
// (the client is not checked yet; RotateRefreshToken consumes it later). A
// replayed token makes the core revoke its whole family.
func (s *storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	tok, err := s.a.core.InspectRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, toTokenError(err)
	}
	as, err := s.a.core.IssueIdentityAssertion(ctx, tok.SessionID, tok.ClientRefID, tok.Scopes)
	if err != nil {
		return nil, toTokenError(err)
	}
	pc, err := s.lookupClient(ctx, as.Audience)
	if err != nil || pc.App.ID != tok.ClientRefID {
		return nil, oidc.ErrInvalidGrant()
	}
	return &refreshRequest{clientRef: tok.ClientRefID, scopes: slices.Clone(tok.Scopes), assertion: as, client: pc}, nil
}

func (s *storage) TerminateSession(context.Context, string, string) error {
	// Never called: TerminateSessionFromRequest below takes precedence.
	return errors.New("oidc: use TerminateSessionFromRequest")
}

// TerminateSessionFromRequest is RP-initiated logout. The library already
// verified the id_token_hint (our signature, our issuer; an expired hint is
// accepted) and the post_logout_redirect_uri. The hint's "sid" tells which
// SSO session to end; endSession (logout.go) decides whether to ask first.
// Without a hint we refuse: anyone could otherwise log a user out with a
// simple link (logout CSRF).
func (s *storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	realm, err := s.realm(ctx)
	if err != nil {
		return "", err
	}
	if req.IDTokenHintClaims == nil || req.IDTokenHintClaims.SessionID == "" {
		return "", oidc.ErrInvalidRequest().WithDescription("id_token_hint is required to log out")
	}
	// No (valid) post_logout_redirect_uri: our own "signed out" page. The
	// library leaves either "" or just "?state=..." in that case.
	redirect := req.RedirectURI
	if redirect == "" || strings.HasPrefix(redirect, "?") {
		redirect = s.a.issuer(realm.Name) + "/oidc/logged-out"
	}
	clientID := req.ClientID
	if clientID == "" && len(req.IDTokenHintClaims.Audience) > 0 {
		clientID = req.IDTokenHintClaims.Audience[0]
	}
	return s.a.endSession(ctx, realm, req.IDTokenHintClaims.SessionID, clientID, redirect)
}

// RevokeToken (RFC 7009). tokenOrTokenID is a jti here: the library first
// turns a refresh token into its id with GetRefreshTokenInfo, and an access
// token (JWT) into its jti. An unknown token, or one of another client, is
// "revoked" without error: RFC 7009, section 2.2 asks for a 200 either way.
func (s *storage) RevokeToken(ctx context.Context, tokenOrTokenID, _ string, clientID string) *oidc.Error {
	pc, err := s.lookupClient(ctx, clientID)
	if err != nil {
		return oidc.ErrInvalidClient()
	}
	tok, err := s.a.core.LookupToken(ctx, tokenOrTokenID)
	if err != nil {
		if errors.Is(err, core.ErrTokenInvalid) {
			return nil
		}
		return oidc.ErrServerError()
	}
	if tok.ClientRefID != pc.App.ID {
		return nil
	}
	if tok.Type == domain.TokenRefreshToken {
		// Revoking a refresh token ends the whole grant, access tokens
		// included (RFC 7009, section 2.1).
		err = s.a.core.RevokeTokenFamily(ctx, tok.FamilyID)
	} else {
		err = s.a.core.RevokeToken(ctx, tok.JTI)
	}
	if err != nil {
		return oidc.ErrServerError()
	}
	return nil
}

// GetRefreshTokenInfo maps a raw refresh token to its id for RevokeToken.
func (s *storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	tok, err := s.a.core.InspectRefreshToken(ctx, token)
	if err != nil {
		if errors.Is(err, core.ErrTokenInvalid) || errors.Is(err, core.ErrTokenReused) {
			return "", "", op.ErrInvalidRefreshToken
		}
		return "", "", err
	}
	return tok.SessionID, tok.JTI, nil
}

// --- claims ----------------------------------------------------------------------

// SetUserinfoFromScopes is deprecated in the library; SetUserinfoFromRequest
// does the work.
func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

// SetUserinfoFromRequest fills the id_token claims.
func (s *storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	as, pc, err := s.requestAssertion(ctx, request)
	if err != nil {
		return err
	}
	info.Subject = as.Subject
	for k, v := range buildClaims(as, pc, scopes, locIDToken, s.a.logger) {
		info.AppendClaims(k, v)
	}
	// "sid" (OIDC Front-Channel Logout, section 3) lets the application ask
	// for a logout of this very session later (id_token_hint at /logout).
	info.AppendClaims("sid", as.SessionID)
	return nil
}

// GetPrivateClaimsFromRequest fills the access token (JWT) claims.
func (s *storage) GetPrivateClaimsFromRequest(ctx context.Context, request op.TokenRequest, scopes []string) (map[string]any, error) {
	as, pc, err := s.requestAssertion(ctx, request)
	if err != nil {
		return nil, err
	}
	claims := buildClaims(as, pc, request.GetScopes(), locAccessToken, s.a.logger)
	// RFC 9068, section 2.2.3: the granted scopes, space separated.
	claims["scope"] = strings.Join(request.GetScopes(), " ")
	claims["sid"] = as.SessionID
	// RFC 9068, section 2.2.3.1: what the user may do. Only the admin
	// console's tokens carry it (see core.IdentityAssertion.Entitlements);
	// never in the ID token or /userinfo.
	if as.Entitlements != nil {
		claims["entitlements"] = as.Entitlements
	}
	return claims, nil
}

func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *storage) requestAssertion(ctx context.Context, request any) (*core.IdentityAssertion, *core.ProtocolClient, error) {
	switch r := request.(type) {
	case *authRequest:
		return s.a.assertionFor(ctx, r)
	case *refreshRequest:
		return r.assertion, r.client, nil
	}
	return nil, nil, fmt.Errorf("oidc: unexpected request type %T", request)
}

// SetUserinfoFromToken answers /userinfo. The library verified the JWT
// (signature, issuer, expiry); here we check the token still exists, is not
// revoked and its session is alive, then compute fresh claims.
func (s *storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	tok, as, pc, err := s.activeAccessToken(ctx, tokenID, subject)
	if err != nil {
		return err
	}
	info.Subject = as.Subject
	for k, v := range buildClaims(as, pc, tok.Scopes, locUserinfo, s.a.logger) {
		info.AppendClaims(k, v)
	}
	return nil
}

// SetIntrospectionFromToken answers /introspect (RFC 7662) for access
// tokens. The caller is an authenticated confidential client of the realm.
func (s *storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, _ string) error {
	tok, as, _, err := s.activeAccessToken(ctx, tokenID, subject)
	if err != nil {
		return err
	}
	realm, _ := realmFrom(ctx)
	resp.Scope = tok.Scopes
	resp.ClientID = as.Audience
	resp.TokenType = oidc.BearerToken
	resp.Expiration = oidc.FromTime(tok.ExpiresAt)
	resp.IssuedAt = oidc.FromTime(tok.IssuedAt)
	resp.AuthTime = oidc.FromTime(as.AuthTime)
	resp.Subject = as.Subject
	resp.Audience = oidc.Audience{as.Audience}
	resp.Issuer = s.a.issuer(realm.Name)
	resp.JWTID = tok.JTI
	resp.AuthenticationMethodsReferences = as.AuthMethods
	return nil
}

func (s *storage) activeAccessToken(ctx context.Context, jti, subject string) (*domain.Token, *core.IdentityAssertion, *core.ProtocolClient, error) {
	tok, err := s.a.core.LookupToken(ctx, jti)
	if err != nil {
		return nil, nil, nil, oidc.ErrAccessDenied().WithDescription("token is not active")
	}
	if tok.Type != domain.TokenAccessToken || tok.Revoked || !s.a.now().Before(tok.ExpiresAt) {
		return nil, nil, nil, oidc.ErrAccessDenied().WithDescription("token is not active")
	}
	as, err := s.a.core.IssueIdentityAssertion(ctx, tok.SessionID, tok.ClientRefID, tok.Scopes)
	if err != nil || as.Subject != subject {
		return nil, nil, nil, oidc.ErrAccessDenied().WithDescription("token is not active")
	}
	pc, err := s.lookupClient(ctx, as.Audience)
	if err != nil || pc.App.ID != tok.ClientRefID {
		return nil, nil, nil, oidc.ErrAccessDenied().WithDescription("token is not active")
	}
	return tok, as, pc, nil
}

// --- JWT profile grant (not supported) -----------------------------------------

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("oidc: private_key_jwt and the JWT bearer grant are not supported")
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("oidc: the JWT bearer grant is not supported")
}

// --- keys --------------------------------------------------------------------------

func (s *storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	realm, err := s.realm(ctx)
	if err != nil {
		return nil, err
	}
	signer, err := s.a.core.Signer(ctx, realm.ID, domain.SigningKeyPurposeJWT)
	if err != nil {
		return nil, err
	}
	alg, err := algFor(signer.KeyType())
	if err != nil {
		return nil, err
	}
	keys, err := s.a.core.PublicKeys(ctx, realm.ID, domain.SigningKeyPurposeJWT)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Kid != signer.KeyID() {
			continue
		}
		pub, err := parsePublicKeyPEM(k.PublicKey)
		if err != nil {
			return nil, err
		}
		return &signingKey{kid: k.Kid, alg: alg, key: &kmsSigner{ctx: ctx, signer: signer, pub: pub, alg: alg}}, nil
	}
	return nil, fmt.Errorf("oidc: public key of %s not found", signer.KeyID())
}

func (s *storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	keys, err := s.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	var algs []jose.SignatureAlgorithm
	for _, k := range keys {
		if !slices.Contains(algs, k.Algorithm()) {
			algs = append(algs, k.Algorithm())
		}
	}
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.RS256}
	}
	return algs, nil
}

func (s *storage) KeySet(ctx context.Context) ([]op.Key, error) {
	realm, err := s.realm(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := s.a.core.PublicKeys(ctx, realm.ID, domain.SigningKeyPurposeJWT)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		alg, err := algFor(k.KeyType)
		if err != nil {
			continue
		}
		pub, err := parsePublicKeyPEM(k.PublicKey)
		if err != nil {
			continue
		}
		out = append(out, &publicKey{kid: k.Kid, alg: alg, key: pub})
	}
	return out, nil
}

func (s *storage) Health(context.Context) error { return nil }

// --- errors ----------------------------------------------------------------------

// toTokenError turns a core error into the OAuth error the client gets.
// Every "this grant is not valid any more" case is invalid_grant, with no
// detail: the client cannot tell a revoked token from a replayed one, and
// does not need to (it starts a new login either way).
func toTokenError(err error) error {
	var oe *oidc.Error
	if errors.As(err, &oe) {
		return oe
	}
	switch {
	case errors.Is(err, core.ErrTokenInvalid),
		errors.Is(err, core.ErrTokenReused),
		errors.Is(err, core.ErrSessionInvalid),
		errors.Is(err, core.ErrForbidden),
		errors.Is(err, core.ErrTimeoutActive),
		errors.Is(err, core.ErrClientNotFound),
		errors.Is(err, core.ErrMFARequired):
		return oidc.ErrInvalidGrant().WithParent(err)
	}
	return oidc.ErrServerError().WithParent(err)
}
