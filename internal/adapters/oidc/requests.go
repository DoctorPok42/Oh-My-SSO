package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core"
)

// Lifetimes of the short-lived login state (oidcstore, i.e. Valkey).
const (
	// authRequestTTL: the user has 10 minutes between /authorize and the
	// code exchange (login page, MFA, passkey included).
	authRequestTTL = 10 * time.Minute
	// codeTTL: an authorization code is exchanged within seconds by a real
	// client. RFC 6749, section 4.1.2 recommends 10 minutes at most.
	codeTTL = time.Minute
)

// Keys in oidcstore. Codes and the browser binding are only ever stored as
// SHA-256 hashes: a dump of Valkey cannot be replayed.
func authRequestKey(id string) string     { return "oidc:ar:{" + id + "}" }
func authRequestCodeKey(id string) string { return "oidc:ar:{" + id + "}:code" }
func codeKey(codeHash string) string      { return "oidc:code:" + codeHash }
func usedCodeKey(codeHash string) string  { return "oidc:usedcode:" + codeHash }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// authRequest is an authorization request between /authorize and the code
// exchange. It is stored as JSON in oidcstore and implements op.AuthRequest
// (what the library reads) and op.TokenRequest / op.IDTokenRequest.
type authRequest struct {
	ID                  string    `json:"id"`
	RealmID             string    `json:"rid"`
	ClientID            string    `json:"cid"`  // public OIDC client_id
	ClientRef           string    `json:"cref"` // ClientApp.ID
	RedirectURI         string    `json:"ruri"`
	State               string    `json:"st,omitempty"`
	Nonce               string    `json:"n,omitempty"`
	Scopes              []string  `json:"sc"`
	ResponseType        string    `json:"rt"`
	ResponseMode        string    `json:"rm,omitempty"`
	CodeChallenge       string    `json:"cc,omitempty"`
	CodeChallengeMethod string    `json:"ccm,omitempty"`
	Prompt              []string  `json:"p,omitempty"`
	MaxAge              *uint     `json:"ma,omitempty"`
	LoginHint           string    `json:"lh,omitempty"`
	BrowserHash         string    `json:"bh"` // SHA-256 of the browser binding cookie
	CreatedAt           time.Time `json:"cat"`

	// Set by the login page once the user is authenticated and allowed.
	Authenticated bool      `json:"done,omitempty"`
	SessionID     string    `json:"sid,omitempty"`
	Subject       string    `json:"sub,omitempty"`
	AuthTime      time.Time `json:"at,omitempty"`
	AMR           []string  `json:"amr,omitempty"`

	// Set when the code is issued.
	CodeHash string `json:"ch,omitempty"`

	// "Pick an account" with prompt=select_account: the one-time token of
	// the page on screen, and whether the user chose to go on with the
	// browser's session.
	PickTokenHash string `json:"pt,omitempty"`
	AccountChosen bool   `json:"ac,omitempty"`

	ConsentTokenHash string             `json:"ct,omitempty"`
	ConsentItems     []core.ConsentItem `json:"ci,omitempty"`
	ConsentDone      bool               `json:"cd,omitempty"`

	// Not stored: computed once per token request (see assertionFor).
	assertion *core.IdentityAssertion
	client    *core.ProtocolClient
}

var (
	_ op.AuthRequest    = (*authRequest)(nil)
	_ op.IDTokenRequest = (*authRequest)(nil)
)

func (a *authRequest) GetID() string         { return a.ID }
func (a *authRequest) GetACR() string        { return "" }
func (a *authRequest) GetAMR() []string      { return a.AMR }
func (a *authRequest) GetAudience() []string { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time {
	return a.AuthTime
}
func (a *authRequest) GetClientID() string { return a.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge, Method: oidc.CodeChallengeMethod(a.CodeChallengeMethod)}
}
func (a *authRequest) GetNonce() string                   { return a.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(a.ResponseMode) }
func (a *authRequest) GetScopes() []string                { return a.Scopes }
func (a *authRequest) GetState() string                   { return a.State }
func (a *authRequest) GetSubject() string                 { return a.Subject }
func (a *authRequest) Done() bool                         { return a.Authenticated }

func (a *authRequest) hasPrompt(p string) bool { return slices.Contains(a.Prompt, p) }

// refreshRequest is a validated refresh_token grant (op.RefreshTokenRequest).
type refreshRequest struct {
	clientRef string
	scopes    []string
	assertion *core.IdentityAssertion
	client    *core.ProtocolClient
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string            { return r.assertion.AuthMethods }
func (r *refreshRequest) GetAudience() []string       { return []string{r.assertion.Audience} }
func (r *refreshRequest) GetAuthTime() time.Time      { return r.assertion.AuthTime }
func (r *refreshRequest) GetClientID() string         { return r.assertion.Audience }
func (r *refreshRequest) GetScopes() []string         { return r.scopes }
func (r *refreshRequest) GetSubject() string          { return r.assertion.Subject }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }


var errAuthRequestNotFound = errors.New("oidc: authorization request not found or expired")

func (a *Adapter) saveAuthRequest(ctx context.Context, ar *authRequest) error {
	data, err := json.Marshal(ar)
	if err != nil {
		return err
	}
	return a.store.Put(ctx, authRequestKey(ar.ID), data, authRequestTTL)
}

// loadAuthRequest returns errAuthRequestNotFound for an unknown, expired or
// other-realm request: a realm never sees another realm's logins.
func (a *Adapter) loadAuthRequest(ctx context.Context, id string) (*authRequest, error) {
	realm, ok := realmFrom(ctx)
	if !ok || id == "" {
		return nil, errAuthRequestNotFound
	}
	data, err := a.store.Get(ctx, authRequestKey(id))
	if err != nil {
		return nil, fmt.Errorf("load authorization request: %w", err)
	}
	if data == nil {
		return nil, errAuthRequestNotFound
	}
	var ar authRequest
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("decode authorization request: %w", err)
	}
	if ar.RealmID != realm.ID || ar.ID != id {
		return nil, errAuthRequestNotFound
	}
	return &ar, nil
}

// assertionFor computes (once per request object) the identity assertion
// the tokens are built from. It is where RBAC, timeouts and the MFA policy
// are checked again at token time: a user who lost access between the login
// and the code exchange gets no token.
func (a *Adapter) assertionFor(ctx context.Context, ar *authRequest) (*core.IdentityAssertion, *core.ProtocolClient, error) {
	if ar.assertion != nil {
		return ar.assertion, ar.client, nil
	}
	if !ar.Authenticated || ar.SessionID == "" {
		return nil, nil, oidc.ErrInvalidGrant().WithDescription("the authorization request was not completed")
	}
	pc, err := a.core.LookupClient(ctx, ar.RealmID, protocolOIDC, ar.ClientID)
	if err != nil {
		return nil, nil, toTokenError(err)
	}
	if pc.App.ID != ar.ClientRef {
		return nil, nil, oidc.ErrInvalidGrant()
	}
	as, err := a.core.IssueIdentityAssertion(ctx, ar.SessionID, ar.ClientRef, ar.Scopes)
	if err != nil {
		return nil, nil, toTokenError(err)
	}
	if as.Subject != ar.Subject {
		// The client's subject_type changed during the login: do not hand
		// out tokens for a subject the login page did not settle on.
		return nil, nil, oidc.ErrInvalidGrant().WithDescription("the subject changed, start the login again")
	}
	if err := a.consentStillValid(ctx, ar, as); err != nil {
		return nil, nil, err
	}
	ar.assertion, ar.client = as, pc
	return as, pc, nil
}
