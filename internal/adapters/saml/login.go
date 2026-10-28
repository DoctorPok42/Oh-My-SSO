package saml

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"

	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

func (a *Adapter) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)

	var p pendingRequest
	if err := a.getJSON(ctx, pendingKey(r.URL.Query().Get("id")), &p, false); err != nil {
		if !errors.Is(err, errNotFound) {
			a.logger.ErrorContext(ctx, "saml: load pending request", "error", err)
		}
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	if p.RealmID != realm.ID {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}
	if !browserMatches(r, &p) {
		a.renderMessage(w, r, http.StatusBadRequest, msgOtherBrowser)
		return
	}
	if r.URL.Query().Get("cancel") == "1" {
		a.sendError(w, r, &p, samllib.StatusResponder, statusAuthnFailed, "the user cancelled the sign-in")
		return
	}

	pc, err := a.core.LookupClient(ctx, realm.ID, domain.ClientAppProtocolSAML2, p.EntityID)
	if err != nil || pc.App.ID != p.ClientRef {
		a.sendError(w, r, &p, samllib.StatusResponder, statusRequestDenied, "the application is not available")
		return
	}
	app := pc.App

	sess := a.currentSession(r, realm)
	if sess == nil || (p.ForceAuthn && sess.CreatedAt.Before(p.CreatedAt)) {
		// ForceAuthn: a login that happens during THIS request (a session
		// created after the request arrived is one).
		if p.IsPassive {
			a.sendError(w, r, &p, samllib.StatusResponder, statusNoPassive, "the user is not signed in")
			return
		}
		a.renderLogin(w, r, &p, app, "login", nil)
		return
	}

	as, err := a.core.IssueIdentityAssertion(ctx, sess.ID, app.ID, nil)
	var mfaErr *core.MFARequiredError
	switch {
	case err == nil:
	case errors.As(err, &mfaErr):
		if p.IsPassive {
			a.sendError(w, r, &p, samllib.StatusResponder, statusNoPassive, "a second factor is required")
			return
		}
		mode := "stepup"
		if mfaErr.EnrollmentRequired {
			mode = "enroll"
		}
		a.renderLogin(w, r, &p, app, mode, mfaErr.AllowedMethods)
		return
	case errors.Is(err, core.ErrSessionInvalid):
		a.renderLogin(w, r, &p, app, "login", nil)
		return
	case errors.Is(err, core.ErrForbidden), errors.Is(err, core.ErrTimeoutActive):
		a.sendError(w, r, &p, samllib.StatusResponder, statusRequestDenied, "the user is not allowed to use this application")
		return
	default:
		a.logger.ErrorContext(ctx, "saml: identity assertion failed", "error", err, "entity_id", app.EntityID)
		a.sendError(w, r, &p, samllib.StatusResponder, "", "")
		return
	}

	if !a.consentStep(w, r, &p, app, sess, as) {
		return
	}

	// The pending request is consumed exactly once: a reload of this page,
	// or a second tab, cannot produce a second assertion.
	var taken pendingRequest
	if err := a.getJSON(ctx, pendingKey(p.ID), &taken, true); err != nil {
		a.renderMessage(w, r, http.StatusBadRequest, msgExpired)
		return
	}

	key, err := a.signingKey(ctx, realm)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: signing key", "error", err)
		a.renderMessage(w, r, http.StatusServiceUnavailable, msgNoKey)
		return
	}

	format := nameIDFormatOf(app)
	nameID, err := nameIDValue(format, as)
	if err != nil {
		a.logger.WarnContext(ctx, "saml: cannot build the NameID", "error", err, "entity_id", app.EntityID)
		a.sendError(w, r, &p, samllib.StatusResponder, statusInvalidNameIDPolicy, err.Error())
		return
	}
	// One record per (session, service provider): its JTI is the
	// SessionIndex, and Single Logout reads it back.
	part, err := a.core.RegisterSessionParticipant(ctx, core.SessionParticipant{
		SessionID: sess.ID, ClientRef: app.ID, Subject: nameID, SubjectFormat: format,
	})
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: register session participant", "error", err)
		a.sendError(w, r, &p, samllib.StatusResponder, "", "")
		return
	}

	out, err := a.assertionResponse(ctx, key, assertionInput{
		realm:        realm,
		app:          app,
		req:          &p,
		as:           as,
		sessionEnd:   sess.ExpiresAt,
		nameID:       part.Subject, // a transient NameID stays the same for the whole session
		nameIDFormat: format,
		sessionIndex: part.JTI,
	})
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: build response", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
		return
	}
	a.logger.InfoContext(ctx, "saml: assertion issued", "entity_id", app.EntityID, "session_id", sess.ID)
	a.postToACS(w, r, &p, out)
}

var errNoEmail = errors.New("the user has no e-mail address, required by this service provider's NameID format")

func nameIDValue(format string, as *core.IdentityAssertion) (string, error) {
	switch format {
	case domain.NameIDFormatEmail:
		email, _ := as.UserAttributes["email"].(string)
		if strings.TrimSpace(email) == "" {
			return "", errNoEmail
		}
		return email, nil
	case domain.NameIDFormatTransient:
		// Random; RegisterSessionParticipant keeps the first one of the
		// session.
		return "_" + rand.Text(), nil
	default: // persistent, unspecified
		return as.Subject, nil
	}
}

func (a *Adapter) renderLogin(w http.ResponseWriter, r *http.Request, p *pendingRequest, app *domain.ClientApp, mode string, allowed []domain.MfaMethodType) {
	realm, _ := realmFrom(r.Context())
	base := "/r/" + realm.Name
	methods := make([]string, 0, len(allowed))
	for _, m := range allowed {
		methods = append(methods, string(m))
	}
	page := loginui.Login{
		RealmDisplay: firstNonEmpty(realm.DisplayName, realm.Name),
		ClientName:   firstNonEmpty(app.Name, app.EntityID),
		ClientParam:  "entity_id",
		ClientID:     app.EntityID,
		Base:         base,
		Assets:       assets(realm),
		Mode:         mode,
		Methods:      strings.Join(methods, ","),
		Passkeys:     a.cfg.PasskeysEnabled,
		CancelURL:    base + "/saml/login?id=" + url.QueryEscape(p.ID) + "&cancel=1",
	}
	if a.cfg.DevPages {
		page.EnrollURL = base + "/dev/mfa"
	}
	if a.cfg.PasswordReset {
		page.ForgotPasswordURL = base + "/auth/forgot-password"
	}
	page.RememberMe, page.RememberMeDays = loginui.RememberMeOffer(a.core.SessionOptions(r.Context(), realm.ID))
	if mode == "login" {
		page.LoginHint, page.Accounts = a.signInChoices(r, realm, app.ID)
		if len(page.Accounts) > 0 {
			page.Mode = "pick"
		}
	}
	a.pages.RenderLogin(w, http.StatusOK, page)
}

// signInChoices: with a session (ForceAuthn), its account pre-filled;
// without one, the accounts remembered on this device ("Pick an account").
func (a *Adapter) signInChoices(r *http.Request, realm Realm, clientRef string) (string, []loginui.Account) {
	ctx := r.Context()
	if sess := a.currentSession(r, realm); sess != nil {
		if acc, err := a.core.SessionAccount(ctx, sess.ID); err == nil {
			return acc.Identifier, nil
		}
		return "", nil
	}
	var device string
	if c, err := r.Cookie(a.cfg.DeviceCookieName); err == nil {
		device = c.Value
	}
	accounts, err := a.core.KnownAccounts(ctx, core.AccountQuery{RealmID: realm.ID, DeviceID: device, ClientRef: clientRef})
	if err != nil {
		a.logger.WarnContext(ctx, "saml: known accounts", "error", err)
		return "", nil
	}
	return "", loginui.AccountsFrom(accounts)
}
