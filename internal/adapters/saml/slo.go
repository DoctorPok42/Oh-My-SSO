package saml

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/beevik/etree"
	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Single Logout (SAML Profiles §4.4), service-provider-initiated.
//
//  1. A service provider sends a signed <LogoutRequest> naming the user
//     (NameID) and its session (SessionIndex).
//  2. We find the IdP session, list its other participants, and revoke it:
//     RevokeSession also revokes every token of the session, OIDC ones
//     included.
//  3. The browser visits each other SAML participant that has an SLO URL:
//     a signed <LogoutRequest> goes out (HTTP-Redirect), its
//     <LogoutResponse> comes back here, then the next one (Step 11 choice:
//     front-channel, through the browser).
//  4. Finally the initiator gets its <LogoutResponse>: Success, with the
//     second-level code PartialLogout when somebody could not be reached.
//
// If a participant never answers (down, or the user closes the tab), the
// chain stops there; the IdP session is already gone, so nothing can
// sign the user in again without a new login.

// logoutRequestLifetime: NotOnOrAfter of the LogoutRequests we send.
const logoutRequestLifetime = 2 * time.Minute

func (a *Adapter) handleSLO(w http.ResponseWriter, r *http.Request) {
	in, err := readInbound(w, r, paramRequest, paramResponse)
	if err != nil {
		a.refuseLogout(w, r, "", err)
		return
	}
	if in.Param == paramResponse {
		a.handleLogoutResponse(w, r, in)
		return
	}
	a.handleLogoutRequest(w, r, in)
}

func (a *Adapter) handleLogoutRequest(w http.ResponseWriter, r *http.Request, in *inbound) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)

	doc, err := parseXML(in.XML)
	if err != nil {
		a.refuseLogout(w, r, "", err)
		return
	}
	root := doc.Root()
	if !isProtocolElement(root, "LogoutRequest") {
		a.refuseLogout(w, r, "", fmt.Errorf("%w: not a LogoutRequest", errInvalidRequest))
		return
	}
	issuer := issuerOf(root)
	pc, err := a.core.LookupClient(ctx, realm.ID, domain.ClientAppProtocolSAML2, issuer)
	if errors.Is(err, core.ErrClientNotFound) {
		a.logger.WarnContext(ctx, "saml: LogoutRequest from an unknown service provider", "issuer", issuer)
		a.renderMessage(w, r, http.StatusBadRequest, msgUnknownApp)
		return
	}
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: lookup service provider", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgLogoutRefused)
		return
	}
	app := pc.App
	// A LogoutRequest must be authenticated (Profiles §4.4.4.1): without a
	// certificate, anybody could log any user out. Step 11 rule: a provider
	// without certificate cannot use Single Logout.
	if !hasCertificates(app) {
		a.refuseLogout(w, r, issuer, errors.New("saml: this service provider has no certificate, it cannot send a LogoutRequest"))
		return
	}
	verified, err := a.verifyInbound(in, root, app)
	if err != nil {
		a.refuseLogout(w, r, issuer, err)
		return
	}
	var req samllib.LogoutRequest
	if err := unmarshalElement(verified, &req); err != nil {
		a.refuseLogout(w, r, issuer, err)
		return
	}
	if err := a.checkLogoutRequest(&req, realm, app); err != nil {
		a.refuseLogout(w, r, issuer, err)
		return
	}
	if first, err := a.firstUse(ctx, app.ID, "logout", req.ID); err != nil || !first {
		if err == nil {
			err = fmt.Errorf("%w: request ID %q already used (replay)", errInvalidRequest, req.ID)
		}
		a.refuseLogout(w, r, issuer, err)
		return
	}

	run := &logoutRun{
		ID:      rand.Text() + rand.Text(),
		RealmID: realm.ID,
		Initiator: &logoutPeer{
			ClientRef: app.ID, EntityID: app.EntityID, SLOURL: app.SLOURL,
			RequestID: req.ID, RelayState: in.RelayState,
		},
	}
	sessionID, err := a.sessionForLogout(r, realm, app, &req)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: find the session to log out", "error", err)
		run.Partial = true
	}
	if sessionID != "" {
		run.SessionID = sessionID
		// List the participants BEFORE revoking: revocation revokes them.
		parts, err := a.core.SessionParticipants(ctx, sessionID)
		if err != nil {
			a.logger.ErrorContext(ctx, "saml: list session participants", "error", err)
			run.Partial = true
		}
		var unreachable bool
		run.Pending, unreachable = a.peersToLogOut(r, parts, app.ID)
		run.Partial = run.Partial || unreachable
		if err := a.core.RevokeSession(ctx, sessionID, domain.SessionRevokedUserLogout); err != nil && !errors.Is(err, core.ErrSessionInvalid) {
			// The one thing that must not fail silently: the IdP session
			// would stay valid while we tell the service provider it is over.
			a.logger.ErrorContext(ctx, "saml: revoke session", "error", err, "session_id", sessionID)
			a.finishLogout(w, r, run, samllib.StatusResponder)
			return
		}
		a.logger.InfoContext(ctx, "saml: single logout", "entity_id", app.EntityID, "session_id", sessionID,
			"other_participants", len(run.Pending))
	}
	a.continueLogout(w, r, run)
}

func (a *Adapter) checkLogoutRequest(req *samllib.LogoutRequest, realm Realm, app *domain.ClientApp) error {
	if req.Version != "2.0" {
		return fmt.Errorf("%w: version %q, expected 2.0", errInvalidRequest, req.Version)
	}
	if err := checkID(req.ID); err != nil {
		return err
	}
	if req.Issuer == nil || req.Issuer.Value != app.EntityID {
		return fmt.Errorf("%w: issuer changed after the signature check", errInvalidRequest)
	}
	if err := a.checkIssueInstant(req.IssueInstant); err != nil {
		return err
	}
	if req.NotOnOrAfter != nil && !a.now().Before(*req.NotOnOrAfter) {
		return fmt.Errorf("%w: LogoutRequest expired", errInvalidRequest)
	}
	// Always signed here, so the destination is mandatory (Bindings §3.4.5.2).
	if req.Destination != a.sloURL(realm) {
		return fmt.Errorf("%w: destination %q is not %q", errInvalidRequest, req.Destination, a.sloURL(realm))
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return fmt.Errorf("%w: missing NameID", errInvalidRequest)
	}
	return nil
}

// sessionForLogout finds the IdP session a LogoutRequest is about: by its
// SessionIndex (the participant record we created), else the browser's own
// session if this provider takes part in it with this NameID. "" when there
// is nothing (left) to log out, which is not an error: logout is idempotent.
func (a *Adapter) sessionForLogout(r *http.Request, realm Realm, app *domain.ClientApp, req *samllib.LogoutRequest) (string, error) {
	ctx := r.Context()
	if req.SessionIndex != nil && req.SessionIndex.Value != "" {
		tok, err := a.core.LookupToken(ctx, req.SessionIndex.Value)
		if errors.Is(err, core.ErrTokenInvalid) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if tok.Type != domain.TokenSAMLSession || tok.ClientRefID != app.ID || tok.Subject != req.NameID.Value {
			a.logger.WarnContext(ctx, "saml: LogoutRequest SessionIndex does not match this provider and NameID", "issuer", app.EntityID)
			return "", nil
		}
		return tok.SessionID, nil
	}
	sess := a.currentSession(r, realm)
	if sess == nil {
		return "", nil
	}
	parts, err := a.core.SessionParticipants(ctx, sess.ID)
	if err != nil {
		return "", err
	}
	for _, p := range parts {
		if p.ClientRefID == app.ID && p.Subject == req.NameID.Value {
			return sess.ID, nil
		}
	}
	return "", nil
}

// peersToLogOut turns participant records into logout targets: one per
// SAML client, except the initiator. A participant without an SLO URL
// cannot be told: the logout is then partial.
func (a *Adapter) peersToLogOut(r *http.Request, parts []*domain.Token, initiatorRef string) ([]logoutPeer, bool) {
	var (
		out         []logoutPeer
		seen        = map[string]bool{initiatorRef: true}
		unreachable bool
	)
	for _, p := range parts {
		if seen[p.ClientRefID] {
			continue
		}
		seen[p.ClientRefID] = true
		pc, err := a.core.ClientByRef(r.Context(), p.ClientRefID)
		if err != nil {
			continue // deleted or disabled since: nothing to tell
		}
		if pc.App.Protocol != domain.ClientAppProtocolSAML2 {
			continue
		}
		if pc.App.SLOURL == "" {
			unreachable = true
			continue
		}
		out = append(out, logoutPeer{
			ClientRef: pc.App.ID, EntityID: pc.App.EntityID, SLOURL: pc.App.SLOURL,
			NameID: p.Subject, NameIDFormat: p.SubjectFormat, SessionIndex: p.JTI,
		})
	}
	return out, unreachable
}

// continueLogout sends the browser to the next participant, or finishes.
func (a *Adapter) continueLogout(w http.ResponseWriter, r *http.Request, run *logoutRun) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	for len(run.Pending) > 0 {
		next := run.Pending[0]
		run.Pending = run.Pending[1:]

		key, err := a.signingKey(ctx, realm)
		if err != nil {
			a.logger.ErrorContext(ctx, "saml: no key to sign a LogoutRequest", "error", err)
			run.Partial = true
			continue
		}
		now := a.now().UTC()
		expires := now.Add(logoutRequestLifetime)
		next.RequestID = newID()
		lr := &samllib.LogoutRequest{
			ID:           next.RequestID,
			Version:      "2.0",
			IssueInstant: now,
			NotOnOrAfter: &expires,
			Destination:  next.SLOURL,
			Issuer:       &samllib.Issuer{Format: nameIDFormatEntity, Value: a.entityID(realm)},
			NameID: &samllib.NameID{
				Format: next.NameIDFormat, NameQualifier: a.entityID(realm), SPNameQualifier: next.EntityID,
				Value: next.NameID,
			},
			SessionIndex: &samllib.SessionIndex{Value: next.SessionIndex},
		}
		u, err := key.redirectURL(ctx, next.SLOURL, paramRequest, xmlBytes(lr.Element()), run.ID)
		if err != nil {
			a.logger.ErrorContext(ctx, "saml: build LogoutRequest", "error", err, "entity_id", next.EntityID)
			run.Partial = true
			continue
		}
		run.Current = &next
		if err := a.putJSON(ctx, logoutKey(run.ID), run, logoutTTL); err != nil {
			a.logger.ErrorContext(ctx, "saml: store logout state", "error", err)
			run.Partial = true
			break
		}
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
	a.finishLogout(w, r, run, samllib.StatusSuccess)
}

// finishLogout answers the initiator, or shows "signed out".
func (a *Adapter) finishLogout(w http.ResponseWriter, r *http.Request, run *logoutRun, top string) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	if err := a.store.Delete(ctx, logoutKey(run.ID)); err != nil {
		a.logger.WarnContext(ctx, "saml: delete logout state", "error", err)
	}
	ini := run.Initiator
	if ini == nil || ini.SLOURL == "" {
		// Nobody to answer (no SLO URL registered for the initiator).
		a.renderMessage(w, r, http.StatusOK, msgLoggedOut)
		return
	}
	key, err := a.signingKey(ctx, realm)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: no key to sign the LogoutResponse", "error", err)
		a.renderMessage(w, r, http.StatusOK, msgLoggedOut)
		return
	}
	status := samllib.Status{StatusCode: samllib.StatusCode{Value: top}}
	if top == samllib.StatusSuccess && run.Partial {
		status.StatusCode.StatusCode = &samllib.StatusCode{Value: statusPartialLogout}
	}
	resp := &samllib.LogoutResponse{
		ID:           newID(),
		InResponseTo: ini.RequestID,
		Version:      "2.0",
		IssueInstant: a.now().UTC(),
		Destination:  ini.SLOURL,
		Issuer:       &samllib.Issuer{Format: nameIDFormatEntity, Value: a.entityID(realm)},
		Status:       status,
	}
	u, err := key.redirectURL(ctx, ini.SLOURL, paramResponse, xmlBytes(resp.Element()), ini.RelayState)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: build LogoutResponse", "error", err)
		a.renderMessage(w, r, http.StatusOK, msgLoggedOut)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// handleLogoutResponse: a participant answers the LogoutRequest we sent.
// Whatever it says, the chain goes on: a refusal or a bad message only
// makes the logout "partial", it must never leave the browser stuck.
func (a *Adapter) handleLogoutResponse(w http.ResponseWriter, r *http.Request, in *inbound) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)

	var run logoutRun
	if err := a.getJSON(ctx, logoutKey(in.RelayState), &run, false); err != nil || run.RealmID != realm.ID || run.Current == nil {
		if err != nil && !errors.Is(err, errNotFound) {
			a.logger.ErrorContext(ctx, "saml: load logout state", "error", err)
		}
		a.renderMessage(w, r, http.StatusBadRequest, msgLogoutExpired)
		return
	}
	cur := run.Current
	run.Current = nil
	if err := a.checkLogoutResponse(r, in, realm, cur); err != nil {
		a.logger.WarnContext(ctx, "saml: LogoutResponse not accepted, logout is partial", "entity_id", cur.EntityID, "error", err)
		run.Partial = true
	}
	a.continueLogout(w, r, &run)
}

func (a *Adapter) checkLogoutResponse(r *http.Request, in *inbound, realm Realm, cur *logoutPeer) error {
	doc, err := parseXML(in.XML)
	if err != nil {
		return err
	}
	root := doc.Root()
	if !isProtocolElement(root, "LogoutResponse") {
		return fmt.Errorf("%w: not a LogoutResponse", errInvalidRequest)
	}
	if issuer := issuerOf(root); issuer != cur.EntityID {
		return fmt.Errorf("%w: issuer %q, expected %q", errInvalidRequest, issuer, cur.EntityID)
	}
	pc, err := a.core.ClientByRef(r.Context(), cur.ClientRef)
	if err != nil {
		return err
	}
	verified, err := a.verifyInbound(in, root, pc.App)
	if err != nil {
		return err
	}
	var resp samllib.LogoutResponse
	if err := unmarshalElement(verified, &resp); err != nil {
		return err
	}
	switch {
	case resp.InResponseTo != cur.RequestID:
		return fmt.Errorf("%w: InResponseTo %q, expected %q", errInvalidRequest, resp.InResponseTo, cur.RequestID)
	case resp.Destination != "" && resp.Destination != a.sloURL(realm):
		return fmt.Errorf("%w: destination %q", errInvalidRequest, resp.Destination)
	case resp.Status.StatusCode.Value != samllib.StatusSuccess:
		return fmt.Errorf("saml: logout status %q", resp.Status.StatusCode.Value)
	}
	return a.checkIssueInstant(resp.IssueInstant)
}

func (a *Adapter) refuseLogout(w http.ResponseWriter, r *http.Request, issuer string, err error) {
	a.logger.WarnContext(r.Context(), "saml: logout request refused", "issuer", issuer, "error", err)
	a.renderMessage(w, r, http.StatusBadRequest, msgLogoutRefused)
}

func xmlBytes(el *etree.Element) []byte {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, _ := doc.WriteToBytes()
	return b
}
