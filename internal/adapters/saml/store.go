package saml

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"sso.internal/sso/internal/core"
)

// Short-lived state of the SAML flows, in oidcstore.Store (Valkey in
// production) under "saml:" keys. Losing it only means "start again".

const (
	// pendingTTL: time to sign in after the service provider sent the user.
	pendingTTL = 10 * time.Minute
	// replayTTL keeps request IDs longer than any request can be accepted
	// (maxRequestAge + clockSkew), so a captured request cannot be replayed.
	replayTTL = 10 * time.Minute
	// logoutTTL: time for the browser to visit every service provider.
	logoutTTL = 10 * time.Minute

	// browserCookieName binds a sign-in to the browser that started it, as
	// the OIDC adapter does (see bindBrowser).
	browserCookieName = "sso_saml_browser"
	browserCookieTTL  = 24 * time.Hour
)

func pendingKey(id string) string { return "saml:ar:{" + id + "}" }
func replayKey(clientRef, kind, requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return "saml:seen:" + kind + ":" + clientRef + ":" + hex.EncodeToString(sum[:])
}
func logoutKey(id string) string { return "saml:lo:{" + id + "}" }

var errNotFound = errors.New("saml: state not found or expired")

// pendingRequest is an AuthnRequest that was accepted and waits for the
// user to sign in. ID travels in the sign-in page URL.
type pendingRequest struct {
	ID          string    `json:"id"`
	RealmID     string    `json:"realm_id"`
	ClientRef   string    `json:"client_ref"`
	EntityID    string    `json:"entity_id"`
	RequestID   string    `json:"request_id"` // AuthnRequest ID -> InResponseTo
	ACSURL      string    `json:"acs_url"`
	RelayState  string    `json:"relay_state,omitempty"`
	ForceAuthn  bool      `json:"force_authn,omitempty"`
	IsPassive   bool      `json:"is_passive,omitempty"`
	BrowserHash string    `json:"browser_hash"`
	CreatedAt   time.Time `json:"created_at"`

	ConsentTokenHash string             `json:"consent_token_hash,omitempty"`
	ConsentItems     []core.ConsentItem `json:"consent_items,omitempty"`
}

// logoutRun is a Single Logout in progress: the IdP session is already
// revoked; the browser visits each other service provider in turn.
type logoutRun struct {
	ID        string `json:"id"`
	RealmID   string `json:"realm_id"`
	SessionID string `json:"session_id"`
	// Initiator: the service provider that asked (nil: IdP-initiated).
	Initiator *logoutPeer `json:"initiator,omitempty"`
	// Pending participants still to log out, in order.
	Pending []logoutPeer `json:"pending"`
	// Current: the participant the browser was just sent to, and the ID of
	// the LogoutRequest it carried (its LogoutResponse must answer it).
	Current *logoutPeer `json:"current,omitempty"`
	// Partial: at least one participant did not confirm.
	Partial bool `json:"partial,omitempty"`
}

type logoutPeer struct {
	ClientRef    string `json:"client_ref"`
	EntityID     string `json:"entity_id"`
	SLOURL       string `json:"slo_url"`
	NameID       string `json:"name_id,omitempty"`
	NameIDFormat string `json:"name_id_format,omitempty"`
	SessionIndex string `json:"session_index,omitempty"`
	// RequestID: the LogoutRequest ID we sent to it, or (initiator) the
	// one it sent to us.
	RequestID  string `json:"request_id,omitempty"`
	RelayState string `json:"relay_state,omitempty"`
}

func (a *Adapter) putJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return a.store.Put(ctx, key, b, ttl)
}

func (a *Adapter) getJSON(ctx context.Context, key string, v any, take bool) error {
	var (
		b   []byte
		err error
	)
	if take {
		b, err = a.store.Take(ctx, key)
	} else {
		b, err = a.store.Get(ctx, key)
	}
	if err != nil {
		return err
	}
	if b == nil {
		return errNotFound
	}
	return json.Unmarshal(b, v)
}

// firstUse records a request ID and reports whether it was new. A SAML
// request ID must be used once (SAML Profiles §4.1.4.5): a replayed one is
// refused.
func (a *Adapter) firstUse(ctx context.Context, clientRef, kind, requestID string) (bool, error) {
	return a.store.PutIfAbsent(ctx, replayKey(clientRef, kind, requestID), []byte{1}, replayTTL)
}


func (a *Adapter) bindBrowser(w http.ResponseWriter, r *http.Request, realm Realm) string {
	v := browserCookieValue(r)
	if v == "" {
		v = rand.Text()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     browserCookieName,
		Value:    v,
		Path:     "/r/" + realm.Name + "/saml",
		MaxAge:   int(browserCookieTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		// Lax: the cookie must come along on the top-level navigation from
		// the service provider (cross-site).
		SameSite: http.SameSiteLaxMode,
	})
	return sha256Hex(v)
}

func browserCookieValue(r *http.Request) string {
	c, err := r.Cookie(browserCookieName)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 64 {
		return ""
	}
	return c.Value
}

func browserMatches(r *http.Request, p *pendingRequest) bool {
	v := browserCookieValue(r)
	return v != "" && subtle.ConstantTimeCompare([]byte(sha256Hex(v)), []byte(p.BrowserHash)) == 1
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// newID returns a SAML ID: an xs:ID must start with a letter or "_".
func newID() string { return "_" + rand.Text() + rand.Text() }

func wrap(err error, what string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("saml: %s: %w", what, err)
}
