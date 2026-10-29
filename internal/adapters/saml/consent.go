package saml

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/clientip"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


const scopeNameIDEmail = "email"

func consentItems(app *domain.ClientApp, as *core.IdentityAssertion) []core.ConsentItem {
	var out []core.ConsentItem
	add := func(it core.ConsentItem) {
		if !slices.ContainsFunc(out, func(x core.ConsentItem) bool { return x.Scope == it.Scope }) {
			out = append(out, it)
		}
	}
	if nameIDFormatOf(app) == domain.NameIDFormatEmail {
		add(core.ConsentItem{Scope: scopeNameIDEmail, Title: "Your e-mail address",
			Description: "The application identifies you by it."})
	}
	for _, cs := range as.Scopes {
		if cs.Protocol == domain.ClientScopeProtocolOIDC {
			continue
		}
		title := strings.TrimSpace(cs.Description)
		if title == "" {
			title = cs.Name
		}
		add(core.ConsentItem{Scope: cs.Name, Title: title})
	}
	return out
}

func itemScopes(items []core.ConsentItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Scope)
	}
	return out
}

// consentStep returns true when the response can be built and sent;
// otherwise it has written the page or the error Response.
func (a *Adapter) consentStep(w http.ResponseWriter, r *http.Request, p *pendingRequest, app *domain.ClientApp,
	sess *domain.Session, as *core.IdentityAssertion) bool {
	ctx := r.Context()
	items := consentItems(app, as)
	dec, err := a.core.CheckConsent(ctx, core.ConsentCheck{SessionID: sess.ID, ClientRef: app.ID, Scopes: itemScopes(items)})
	switch {
	case err == nil:
	case errors.Is(err, core.ErrSessionInvalid):
		a.renderLogin(w, r, p, app, "login", nil)
		return false
	default:
		a.logger.ErrorContext(ctx, "saml: consent check failed", "error", err, "entity_id", app.EntityID)
		a.sendError(w, r, p, samllib.StatusResponder, "", "")
		return false
	}
	if !dec.Required {
		return true
	}
	if p.IsPassive {
		a.sendError(w, r, p, samllib.StatusResponder, statusNoPassive, "the user must approve this service provider first")
		return false
	}
	a.renderConsent(w, r, p, app, as, items, dec)
	return false
}

func (a *Adapter) renderConsent(w http.ResponseWriter, r *http.Request, p *pendingRequest, app *domain.ClientApp,
	as *core.IdentityAssertion, items []core.ConsentItem, dec *core.ConsentDecision) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)

	token := rand.Text()
	p.ConsentTokenHash = sha256Hex(token)
	p.ConsentItems = items
	if !a.savePendingKeepDeadline(r, p) {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
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
		ClientName:     firstNonEmpty(app.Name, app.EntityID),
		ClientHost:     hostOf(p.ACSURL),
		Username:       userLabel(as),
		Items:          lines,
		MoreThanBefore: dec.Previously && len(dec.Missing) > 0,
		Action:         "/r/" + realm.Name + "/saml/consent",
		RequestID:      p.ID,
		Token:          token,
		Assets:         assets(realm),
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
	var p pendingRequest
	if err := a.getJSON(ctx, pendingKey(r.PostForm.Get("id")), &p, false); err != nil || p.RealmID != realm.ID {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	if !browserMatches(r, &p) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	loginURL := a.realmBase(realm) + "/login?id=" + url.QueryEscape(p.ID)
	token := r.PostForm.Get("consent_token")
	if p.ConsentTokenHash == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(sha256Hex(token)), []byte(p.ConsentTokenHash)) != 1 {
		http.Redirect(w, r, loginURL, http.StatusSeeOther) // stale or forged form: decide again
		return
	}
	items := p.ConsentItems
	p.ConsentTokenHash, p.ConsentItems = "", nil
	if !a.savePendingKeepDeadline(r, &p) {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}

	sess := a.currentSession(r, realm)
	if sess == nil {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}
	switch r.PostForm.Get("decision") {
	case "allow":
		_, err := a.core.GrantConsent(ctx, core.ConsentGrant{
			SessionID: sess.ID, ClientRef: p.ClientRef, Items: items,
			IPAddress: remoteIP(r), UserAgent: r.UserAgent(),
		})
		switch {
		case err == nil, errors.Is(err, core.ErrSessionInvalid):
			// The sign-in page checks everything again and sends the
			// Response (or asks for the password if the session ended).
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
		case errors.Is(err, core.ErrClientNotFound):
			a.sendError(w, r, &p, samllib.StatusResponder, statusRequestDenied, "the application is not available")
		default:
			a.logger.ErrorContext(ctx, "saml: grant consent", "error", err, "entity_id", p.EntityID)
			a.sendError(w, r, &p, samllib.StatusResponder, "", "")
		}
	case "deny":
		if err := a.core.DenyConsent(ctx, core.ConsentDenial{
			SessionID: sess.ID, ClientRef: p.ClientRef, Scopes: itemScopes(items),
			IPAddress: remoteIP(r), UserAgent: r.UserAgent(),
		}); err != nil {
			a.logger.WarnContext(ctx, "saml: record consent denial", "error", err)
		}
		a.sendError(w, r, &p, samllib.StatusResponder, statusRequestDenied, "the user denied access")
	default:
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	}
}

// savePendingKeepDeadline stores the pending request again without giving
// it more time (pendingTTL after /saml/sso, however often the page reloads).
func (a *Adapter) savePendingKeepDeadline(r *http.Request, p *pendingRequest) bool {
	left := pendingTTL - a.now().Sub(p.CreatedAt)
	if left <= 0 {
		return false
	}
	if err := a.putJSON(r.Context(), pendingKey(p.ID), p, left); err != nil {
		a.logger.ErrorContext(r.Context(), "saml: store pending request", "error", err)
		return false
	}
	return true
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

// remoteIP: the client address found by the router's middleware (the TCP
// peer, or what a trusted reverse proxy reported, see internal/clientip).
func remoteIP(r *http.Request) string {
	return clientip.FromRequest(r)
}
