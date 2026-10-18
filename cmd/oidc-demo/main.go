// oidc-demo is a tiny OpenID Connect "relying party" (an application that
// lets Oh-My-SSO log its users in). It exists to try Step 10 by hand and to
// read, in one file, what a real client does:
//
//  1. discovery: read /.well-known/openid-configuration of the issuer;
//  2. /login: authorization code flow with PKCE, state and nonce;
//  3. /callback: exchange the code, verify the id_token (signature with the
//     JWKS, iss, aud, exp, nonce);
//  4. refresh (rotation), userinfo, logout (RP-initiated logout).
//
// It only uses golang.org/x/oauth2 and go-jose, like most Go applications.
// A demo, not a library: sessions live in memory, one process.
//
//	go run ./cmd/oidc-demo -issuer http://localhost:8080/r/demo -client-id demo -client-secret ...
//
// or with DEMO_ISSUER, DEMO_CLIENT_ID, DEMO_CLIENT_SECRET, DEMO_ADDR in the
// environment (`make oidc-demo` loads .env).
//
// Docs: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// and https://pkg.go.dev/golang.org/x/oauth2
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

//go:embed page.html
var pageFS embed.FS

var page = template.Must(template.ParseFS(pageFS, "page.html"))

// discovery is the part of the discovery document this demo uses.
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// session of one browser in this demo application (not the SSO session).
type session struct {
	// Login in progress: the values the callback must find again.
	state, nonce, verifier string

	token        *oauth2.Token
	idToken      string
	idClaims     map[string]any
	oldRefresh   string // the refresh token before the last rotation
	lastResult   string // what the last action returned, shown on the page
	lastResultOK bool
}

type app struct {
	issuer   string
	base     string // this application's URL, e.g. http://localhost:9000
	disc     discovery
	oauth    *oauth2.Config
	client   *http.Client
	mu       sync.Mutex
	sessions map[string]*session
	jwks     jose.JSONWebKeySet
}

func main() {
	issuer := flag.String("issuer", envOr("DEMO_ISSUER", "http://localhost:8080/r/demo"), "issuer URL (PUBLIC_URL/r/<realm>)")
	clientID := flag.String("client-id", envOr("DEMO_CLIENT_ID", "demo"), "client_id")
	clientSecret := flag.String("client-secret", os.Getenv("DEMO_CLIENT_SECRET"), "client_secret (empty: public client)")
	addr := flag.String("addr", envOr("DEMO_ADDR", "localhost:9000"), "listen address of this demo")
	flag.Parse()

	a := &app{
		issuer:   strings.TrimRight(*issuer, "/"),
		base:     "http://" + *addr,
		client:   &http.Client{Timeout: 10 * time.Second},
		sessions: map[string]*session{},
	}
	ctx := context.Background()
	if err := a.discover(ctx); err != nil {
		log.Fatalf("discovery: %v (is the IdP running? is DEMO_ISSUER right?)", err)
	}
	a.oauth = &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		RedirectURL:  a.base + "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.disc.AuthorizationEndpoint,
			TokenURL: a.disc.TokenEndpoint,
			// client_secret_basic (the default of `idp oidc clients create`).
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		// offline_access asks for a refresh token.
		Scopes: []string{"openid", "profile", "email", "offline_access"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /callback", a.callback)
	mux.HandleFunc("POST /refresh", a.refresh)
	mux.HandleFunc("POST /replay", a.replay)
	mux.HandleFunc("POST /userinfo", a.userinfo)
	mux.HandleFunc("POST /logout", a.logout)

	log.Printf("oidc-demo: issuer %s, client_id %s", a.issuer, *clientID)
	log.Printf("oidc-demo: open %s/", a.base)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// --- discovery and keys ------------------------------------------------------

func (a *app) discover(ctx context.Context) error {
	if err := a.getJSON(ctx, a.issuer+"/.well-known/openid-configuration", &a.disc); err != nil {
		return err
	}
	// OIDC Discovery 4.3: the issuer in the document must be exactly the one
	// we asked for, or someone is impersonating the IdP.
	if a.disc.Issuer != a.issuer {
		return fmt.Errorf("issuer mismatch: asked %q, document says %q", a.issuer, a.disc.Issuer)
	}
	return a.getJSON(ctx, a.disc.JWKSURI, &a.jwks)
}

func (a *app) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// key returns the public key of a kid, reloading the JWKS once when it is
// unknown (the IdP rotated its key, Step 8).
func (a *app) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	a.mu.Lock()
	keys := a.jwks.Key(kid)
	a.mu.Unlock()
	if len(keys) == 0 {
		var set jose.JSONWebKeySet
		if err := a.getJSON(ctx, a.disc.JWKSURI, &set); err != nil {
			return nil, err
		}
		a.mu.Lock()
		a.jwks = set
		keys = a.jwks.Key(kid)
		a.mu.Unlock()
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key %q in the JWKS", kid)
	}
	return &keys[0], nil
}

// verifyIDToken does what OIDC Core 3.1.3.7 asks a client to do.
func (a *app) verifyIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	key, err := a.key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	claims := map[string]any{}
	if err := tok.Claims(key.Key, &std, &claims); err != nil { // checks the signature
		return nil, fmt.Errorf("signature: %w", err)
	}
	err = std.ValidateWithLeeway(jwt.Expected{
		Issuer:      a.issuer,
		AnyAudience: jwt.Audience{a.oauth.ClientID},
		Time:        time.Now(),
	}, time.Minute)
	if err != nil {
		return nil, err
	}
	if len(std.Audience) > 1 && claims["azp"] != a.oauth.ClientID {
		return nil, errors.New("azp is not our client_id")
	}
	// nonce: only in the id_token of the login, bound to this browser.
	if nonce != "" && claims["nonce"] != nonce {
		return nil, errors.New("nonce mismatch (replayed id_token?)")
	}
	return claims, nil
}

// --- browser session of the demo -------------------------------------------------

const cookieName = "demo_sid"

func (a *app) session(w http.ResponseWriter, r *http.Request) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, err := r.Cookie(cookieName); err == nil {
		if s, ok := a.sessions[c.Value]; ok {
			return s
		}
	}
	id := rand.Text()
	s := &session{}
	a.sessions[id] = s
	// SameSite=Lax: sent on the top-level redirect back from the IdP.
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return s
}

func (a *app) render(w http.ResponseWriter, s *session) {
	data := map[string]any{
		"Issuer":   a.issuer,
		"ClientID": a.oauth.ClientID,
		"LoggedIn": s.token != nil,
		"Result":   s.lastResult,
		"ResultOK": s.lastResultOK,
	}
	if s.token != nil {
		data["IDClaims"] = pretty(s.idClaims)
		data["AccessClaims"] = pretty(unverifiedClaims(s.token.AccessToken))
		data["AccessExpiry"] = s.token.Expiry.Format(time.TimeOnly)
		data["Refresh"] = short(s.token.RefreshToken)
		data["OldRefresh"] = short(s.oldRefresh)
		data["Scope"] = s.token.Extra("scope")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, data); err != nil {
		log.Printf("render: %v", err)
	}
}

func (a *app) setResult(s *session, ok bool, format string, args ...any) {
	a.mu.Lock()
	s.lastResult, s.lastResultOK = fmt.Sprintf(format, args...), ok
	a.mu.Unlock()
}

// --- handlers ----------------------------------------------------------------------

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.render(w, s)
}

// login starts the authorization code flow.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.mu.Lock()
	s.state = rand.Text()                  // against CSRF on /callback
	s.nonce = rand.Text()                  // binds the id_token to this login
	s.verifier = oauth2.GenerateVerifier() // PKCE (RFC 7636)
	state, nonce, verifier := s.state, s.nonce, s.verifier
	a.mu.Unlock()

	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	if p := r.URL.Query().Get("prompt"); p != "" { // e.g. /login?prompt=login
		opts = append(opts, oauth2.SetAuthURLParam("prompt", p))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// callback is the redirect_uri: the IdP sends the browser back here with
// ?code=...&state=... (or ?error=...).
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	q := r.URL.Query()
	a.mu.Lock()
	state, nonce, verifier := s.state, s.nonce, s.verifier
	s.state, s.nonce, s.verifier = "", "", "" // single use
	a.mu.Unlock()

	switch {
	case q.Get("error") != "":
		a.setResult(s, false, "The IdP answered error=%s: %s", q.Get("error"), q.Get("error_description"))
	case state == "" || q.Get("state") != state:
		a.setResult(s, false, "state mismatch: this callback was not started by this browser (CSRF?)")
	default:
		ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
		tok, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			a.setResult(s, false, "code exchange failed: %v", err)
			break
		}
		raw, _ := tok.Extra("id_token").(string)
		claims, err := a.verifyIDToken(ctx, raw, nonce)
		if err != nil {
			a.setResult(s, false, "id_token rejected: %v", err)
			break
		}
		a.mu.Lock()
		s.token, s.idToken, s.idClaims, s.oldRefresh = tok, raw, claims, ""
		a.mu.Unlock()
		a.setResult(s, true, "Logged in as %v. The id_token signature, issuer, audience, expiry and nonce are valid.", claims["sub"])
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// refresh uses the refresh token. The IdP rotates it: the old one is now
// "used", and using it again is treated as a theft (see /replay).
func (a *app) refresh(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.mu.Lock()
	cur := s.token
	a.mu.Unlock()
	if cur == nil || cur.RefreshToken == "" {
		a.setResult(s, false, "no refresh token (the client needs the offline_access scope)")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tok, err := a.refreshWith(r.Context(), cur.RefreshToken)
	if err != nil {
		a.setResult(s, false, "refresh failed: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// A refresh may return a new id_token (no nonce in it this time).
	raw, _ := tok.Extra("id_token").(string)
	var claims map[string]any
	if raw != "" {
		if claims, err = a.verifyIDToken(r.Context(), raw, ""); err != nil {
			a.setResult(s, false, "id_token from the refresh rejected: %v", err)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	a.mu.Lock()
	s.oldRefresh, s.token = cur.RefreshToken, tok
	if claims != nil {
		s.idToken, s.idClaims = raw, claims
	}
	a.mu.Unlock()
	a.setResult(s, true, "New access token and NEW refresh token (rotation). The old refresh token is now used.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// replay sends the previous refresh token again, like an attacker who stole
// it would. The IdP refuses it AND revokes the whole token family: the
// current refresh token stops working too (RFC 9700, section 4.14.2).
func (a *app) replay(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.mu.Lock()
	old := s.oldRefresh
	a.mu.Unlock()
	if old == "" {
		a.setResult(s, false, "refresh once first: there is no old refresh token yet")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := a.refreshWith(r.Context(), old); err != nil {
		a.setResult(s, true, "Refused, as expected: %v. The whole family is revoked: try Refresh now, it fails too.", err)
	} else {
		a.setResult(s, false, "The old refresh token was accepted: reuse detection is broken!")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) refreshWith(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	// An expired token forces the TokenSource to use the refresh token.
	return a.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Unix(1, 0)}).Token()
}

// userinfo calls the UserInfo endpoint with the access token.
func (a *app) userinfo(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.mu.Lock()
	tok := s.token
	a.mu.Unlock()
	if tok == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, a.disc.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := a.client.Do(req)
	if err != nil {
		a.setResult(s, false, "userinfo: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		a.setResult(s, false, "userinfo: %s %s %s", resp.Status, resp.Header.Get("WWW-Authenticate"), body)
	} else {
		var v any
		_ = json.Unmarshal(body, &v)
		a.setResult(s, true, "UserInfo:\n%s", pretty(v))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout ends the local session, then asks the IdP to end the SSO session
// (RP-initiated logout). The IdP comes back to post_logout_redirect_uri.
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	s := a.session(w, r)
	a.mu.Lock()
	idToken := s.idToken
	*s = session{}
	a.mu.Unlock()
	if idToken == "" || a.disc.EndSessionEndpoint == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {a.base + "/"},
		"client_id":                {a.oauth.ClientID},
	}
	http.Redirect(w, r, a.disc.EndSessionEndpoint+"?"+q.Encode(), http.StatusSeeOther)
}

// --- helpers --------------------------------------------------------------------

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// unverifiedClaims decodes a JWT payload WITHOUT checking it, for display
// only. An application never trusts the access token itself: it is for the
// APIs it calls, which verify it with the JWKS.
func unverifiedClaims(raw string) any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "(not a JWT)"
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "(undecodable)"
	}
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-6:]
}
