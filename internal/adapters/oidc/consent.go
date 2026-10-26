package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


var standardConsentItems = map[string]core.ConsentItem{
	scopeProfile: {Scope: scopeProfile, Title: "Your profile",
		Description: "Your name, username and the other details of your profile (picture, language...)."},
	scopeEmail: {Scope: scopeEmail, Title: "Your e-mail address"},
	scopeOfflineAccess: {Scope: scopeOfflineAccess, Title: "Stay signed in",
		Description: "The application can renew its access without asking you again, while you are signed in here."},
}

// consentItems lists what the client is about to receive: the standard
// scopes it was granted, then the effective ClientScopes of the assertion
// (the ones it asked for, plus the realm's default scopes, which also
// produce claims). "openid" is not an item: the identity line of the page
// covers it.
func consentItems(ar *authRequest, as *core.IdentityAssertion) []core.ConsentItem {
	var out []core.ConsentItem
	add := func(it core.ConsentItem) {
		if !slices.ContainsFunc(out, func(x core.ConsentItem) bool { return x.Scope == it.Scope }) {
			out = append(out, it)
		}
	}
	for _, sc := range ar.Scopes {
		if it, ok := standardConsentItems[sc]; ok {
			add(it)
		}
	}
	for _, cs := range as.Scopes {
		if cs.Protocol == domain.ClientScopeProtocolSAML2 {
			continue
		}
		add(clientScopeItem(cs))
	}
	return out
}

func clientScopeItem(cs *domain.ClientScope) core.ConsentItem {
	title := strings.TrimSpace(cs.Description)
	if title == "" {
		title = cs.Name
	}
	return core.ConsentItem{Scope: cs.Name, Title: title}
}

func itemScopes(items []core.ConsentItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Scope)
	}
	return out
}

// consentStep runs in handleLogin once the assertion is known. It returns
// true when the flow can go on to the callback; otherwise it has written
// the response (consent page, or an error for the application).
func (a *Adapter) consentStep(w http.ResponseWriter, r *http.Request, ar *authRequest, pc *core.ProtocolClient,
	sess *domain.Session, as *core.IdentityAssertion) bool {
	ctx := r.Context()
	items := consentItems(ar, as)
	dec, err := a.core.CheckConsent(ctx, core.ConsentCheck{
		SessionID: sess.ID,
		ClientRef: pc.App.ID,
		Scopes:    itemScopes(items),
		// prompt=consent asks for the screen once per request: after
		// "Allow", the reload must go on.
		Force: ar.hasPrompt(oidc.PromptConsent) && !ar.ConsentDone,
	})
	switch {
	case err == nil:
	case errors.Is(err, core.ErrSessionInvalid):
		a.renderLogin(w, r, ar, pc, "login", nil)
		return false
	default:
		a.logger.ErrorContext(ctx, "oidc: consent check failed", "error", err, "client_id", ar.ClientID)
		a.authError(w, r, ar, oidc.ErrServerError())
		return false
	}
	if !dec.Required {
		return true
	}
	if ar.hasPrompt(oidc.PromptNone) {
		e := oidc.ErrInteractionRequired().WithDescription("the user must approve this application first")
		e.ErrorType = "consent_required"
		a.authError(w, r, ar, e)
		return false
	}
	a.renderConsent(w, r, ar, pc, as, items, dec)
	return false
}

func (a *Adapter) renderConsent(w http.ResponseWriter, r *http.Request, ar *authRequest, pc *core.ProtocolClient,
	as *core.IdentityAssertion, items []core.ConsentItem, dec *core.ConsentDecision) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	base := "/r/" + realm.Name

	// A new token at each display: only the form on screen can answer.
	token := rand.Text()
	ar.ConsentTokenHash = sha256Hex(token)
	ar.ConsentItems = items
	if err := a.saveAuthRequestKeepDeadline(ctx, ar); err != nil {
		if errors.Is(err, errAuthRequestNotFound) {
			a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
			return
		}
		a.logger.ErrorContext(ctx, "oidc: save authorization request", "error", err)
		a.authError(w, r, ar, oidc.ErrServerError())
		return
	}

	lines := make([]loginui.ConsentLine, 0, len(items))
	for _, it := range items {
		lines = append(lines, loginui.ConsentLine{
			Title: it.Title, Description: it.Description,
			New: dec.Previously && slices.Contains(dec.Missing, it.Scope),
		})
	}
	a.pages.RenderConsent(w, loginui.Consent{
		RealmDisplay:   firstNonEmpty(realm.DisplayName, realm.Name),
		ClientName:     firstNonEmpty(pc.App.Name, pc.App.ClientID),
		ClientHost:     hostOf(ar.RedirectURI),
		Username:       userLabel(as),
		Items:          lines,
		MoreThanBefore: dec.Previously && len(dec.Missing) > 0,
		Action:         base + "/oidc/consent",
		RequestID:      ar.ID,
		Token:          token,
		Assets:         base + "/oidc/assets",
	})
}

// handleConsent receives the answer of the consent page.
func (a *Adapter) handleConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	ar, err := a.loadAuthRequest(ctx, r.PostForm.Get("id"))
	if err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	if !browserMatches(r, ar) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	loginURL := a.issuer(realm.Name) + "/oidc/login?id=" + url.QueryEscape(ar.ID)
	if ar.Authenticated {
		a.redirectToCallback(w, r, ar)
		return
	}
	// The token of the form on screen, once. A stale or forged form just
	// goes back to the login page, which decides again (and shows a fresh
	// consent page if still needed).
	token := r.PostForm.Get("consent_token")
	if ar.ConsentTokenHash == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(token)), []byte(ar.ConsentTokenHash)) != 1 {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	items := ar.ConsentItems
	ar.ConsentTokenHash, ar.ConsentItems = "", nil
	if err := a.saveAuthRequestKeepDeadline(ctx, ar); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}

	sess := a.currentSession(r, realm)
	if sess == nil {
		http.Redirect(w, r, loginURL, http.StatusSeeOther) // signed out meanwhile: password form
		return
	}

	switch r.PostForm.Get("decision") {
	case "allow":
		_, err := a.core.GrantConsent(ctx, core.ConsentGrant{
			SessionID: sess.ID, ClientRef: ar.ClientRef, Items: items,
			IPAddress: remoteIP(r), UserAgent: r.UserAgent(),
		})
		switch {
		case err == nil:
		case errors.Is(err, core.ErrSessionInvalid):
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		case errors.Is(err, core.ErrClientNotFound):
			a.authError(w, r, ar, oidc.ErrAccessDenied().WithDescription("the application is not available"))
			return
		default:
			a.logger.ErrorContext(ctx, "oidc: grant consent", "error", err, "client_id", ar.ClientID)
			a.authError(w, r, ar, oidc.ErrServerError())
			return
		}
		ar.ConsentDone = true
		if err := a.saveAuthRequestKeepDeadline(ctx, ar); err != nil {
			a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
			return
		}
		// The login page checks everything again, then goes to the callback.
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	case "deny":
		if err := a.core.DenyConsent(ctx, core.ConsentDenial{
			SessionID: sess.ID, ClientRef: ar.ClientRef, Scopes: itemScopes(items),
			IPAddress: remoteIP(r), UserAgent: r.UserAgent(),
		}); err != nil {
			a.logger.WarnContext(ctx, "oidc: record consent denial", "error", err)
		}
		a.authError(w, r, ar, oidc.ErrAccessDenied().WithDescription("the user denied access"))
	default:
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	}
}

// consentStillValid is checked again at the code exchange: a consent revoked
// in the seconds between the login page and /token gives no token.
func (a *Adapter) consentStillValid(ctx context.Context, ar *authRequest, as *core.IdentityAssertion) error {
	dec, err := a.core.CheckConsent(ctx, core.ConsentCheck{
		SessionID: ar.SessionID, ClientRef: ar.ClientRef, Scopes: itemScopes(consentItems(ar, as)),
	})
	if err != nil {
		return toTokenError(err)
	}
	if dec.Required {
		return oidc.ErrInvalidGrant().WithDescription("the user's consent is missing, start the sign-in again")
	}
	return nil
}

// saveAuthRequestKeepDeadline stores the request again without giving it
// more time: it still expires authRequestTTL after /authorize, however
// often the consent page is reloaded.
func (a *Adapter) saveAuthRequestKeepDeadline(ctx context.Context, ar *authRequest) error {
	left := authRequestTTL - a.now().Sub(ar.CreatedAt)
	if left <= 0 {
		return errAuthRequestNotFound
	}
	data, err := json.Marshal(ar)
	if err != nil {
		return err
	}
	return a.store.Put(ctx, authRequestKey(ar.ID), data, left)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func userLabel(as *core.IdentityAssertion) string {
	for _, k := range []string{"username", "email"} {
		if v, ok := as.UserAttributes[k].(string); ok && v != "" {
			return v
		}
	}
	return "your account"
}

// remoteIP: the router's RealIP middleware already put the client address
// in RemoteAddr.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
