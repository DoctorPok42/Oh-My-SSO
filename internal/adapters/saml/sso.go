package saml

import (
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Web Browser SSO, step 1: the service provider sends an <AuthnRequest>
// (SAML Profiles §4.1). It is checked, remembered, and the browser goes to
// the sign-in page.

const (
	// clockSkew tolerated between our clock and the service provider's.
	clockSkew = 90 * time.Second
	// requestMaxAge: an AuthnRequest / LogoutRequest is processed the moment
	// it arrives, so it must be recent (plus clockSkew).
	requestMaxAge = 90 * time.Second
	maxIDLength   = 256
)

var errInvalidRequest = errors.New("saml: invalid request")

func (a *Adapter) handleSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)

	in, err := readInbound(w, r, paramRequest)
	if err != nil {
		a.refuse(w, r, "", err)
		return
	}
	doc, err := parseXML(in.XML)
	if err != nil {
		a.refuse(w, r, "", err)
		return
	}
	root := doc.Root()
	if !isProtocolElement(root, "AuthnRequest") {
		a.refuse(w, r, "", fmt.Errorf("%w: not an AuthnRequest", errInvalidRequest))
		return
	}

	// The issuer tells which service provider (and which certificates) to
	// use. It is read from the message as received; everything else is read
	// again from what the signature check returns.
	issuer := issuerOf(root)
	pc, err := a.core.LookupClient(ctx, realm.ID, domain.ClientAppProtocolSAML2, issuer)
	if errors.Is(err, core.ErrClientNotFound) {
		a.logger.WarnContext(ctx, "saml: AuthnRequest from an unknown service provider", "issuer", issuer)
		a.renderMessage(w, r, http.StatusBadRequest, msgUnknownApp)
		return
	}
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: lookup service provider", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
		return
	}
	app := pc.App

	verified, err := a.verifyInbound(in, root, app)
	if err != nil {
		a.refuse(w, r, issuer, err)
		return
	}
	var req samllib.AuthnRequest
	if err := unmarshalElement(verified, &req); err != nil {
		a.refuse(w, r, issuer, err)
		return
	}
	signed := in.SigAlg != "" || childNS(verified, "http://www.w3.org/2000/09/xmldsig#", "Signature") != nil
	if err := a.checkAuthnRequest(&req, realm, app, signed); err != nil {
		a.refuse(w, r, issuer, err)
		return
	}
	if first, err := a.firstUse(ctx, app.ID, "authn", req.ID); err != nil {
		a.logger.ErrorContext(ctx, "saml: replay cache", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
		return
	} else if !first {
		a.refuse(w, r, issuer, fmt.Errorf("%w: request ID %q already used (replay)", errInvalidRequest, req.ID))
		return
	}

	p := &pendingRequest{
		ID:         rand.Text() + rand.Text(),
		RealmID:    realm.ID,
		ClientRef:  app.ID,
		EntityID:   app.EntityID,
		RequestID:  req.ID,
		ACSURL:     app.ACSURL, // ours, never the request's: see checkAuthnRequest
		RelayState: in.RelayState,
		ForceAuthn: req.ForceAuthn != nil && *req.ForceAuthn,
		IsPassive:  req.IsPassive != nil && *req.IsPassive,
		CreatedAt:  a.now(),
	}

	// From here on, the destination is the registered ACS URL: problems are
	// reported to the service provider with a SAML status.
	if req.ProtocolBinding != "" && req.ProtocolBinding != bindingPOST {
		a.sendError(w, r, p, samllib.StatusRequester, statusUnsupportedBinding,
			"responses are only sent with the HTTP-POST binding")
		return
	}
	if req.NameIDPolicy != nil && req.NameIDPolicy.Format != nil {
		if f := *req.NameIDPolicy.Format; f != "" && f != domain.NameIDFormatUnspecified && f != nameIDFormatOf(app) {
			a.sendError(w, r, p, samllib.StatusRequester, statusInvalidNameIDPolicy,
				"this service provider is configured for NameID format "+nameIDFormatOf(app))
			return
		}
	}

	p.BrowserHash = a.bindBrowser(w, r, realm)
	if err := a.putJSON(ctx, pendingKey(p.ID), p, pendingTTL); err != nil {
		a.logger.ErrorContext(ctx, "saml: store pending request", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
		return
	}
	http.Redirect(w, r, a.realmBase(realm)+"/login?id="+url.QueryEscape(p.ID), http.StatusFound)
}

// checkAuthnRequest applies SAML Core §3.4 and Profiles §4.1.4.1 to what
// the service provider asked for.
func (a *Adapter) checkAuthnRequest(req *samllib.AuthnRequest, realm Realm, app *domain.ClientApp, signed bool) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errInvalidRequest, fmt.Sprintf(format, args...))
	}
	if req.Version != "2.0" {
		return bad("version %q, expected 2.0", req.Version)
	}
	if err := checkID(req.ID); err != nil {
		return err
	}
	if req.Issuer == nil || req.Issuer.Value != app.EntityID {
		return bad("issuer changed after the signature check")
	}
	if err := a.checkIssueInstant(req.IssueInstant); err != nil {
		return err
	}
	// A signed message must name its destination, and any destination
	// given must be us (Bindings §3.4.5.2 and §3.5.5.2): a request signed for
	// another IdP cannot be replayed here.
	if req.Destination != "" && req.Destination != a.ssoURL(realm) {
		return bad("destination %q is not %q", req.Destination, a.ssoURL(realm))
	}
	if signed && req.Destination == "" {
		return bad("a signed request must have a Destination")
	}
	// The assertion only ever goes to the registered ACS URL: a request
	// naming another one is refused, not redirected (that would hand the
	// assertion to whoever crafted the request).
	if app.ACSURL == "" {
		return bad("service provider %s has no ACS URL configured", app.EntityID)
	}
	if req.AssertionConsumerServiceURL != "" && req.AssertionConsumerServiceURL != app.ACSURL {
		return bad("ACS URL %q is not the registered one", req.AssertionConsumerServiceURL)
	}
	return nil
}

func (a *Adapter) checkIssueInstant(t time.Time) error {
	now := a.now()
	switch {
	case t.IsZero():
		return fmt.Errorf("%w: missing IssueInstant", errInvalidRequest)
	case t.After(now.Add(clockSkew)):
		return fmt.Errorf("%w: IssueInstant %s is in the future", errInvalidRequest, t.UTC().Format(time.RFC3339))
	case t.Before(now.Add(-requestMaxAge - clockSkew)):
		return fmt.Errorf("%w: IssueInstant %s is too old", errInvalidRequest, t.UTC().Format(time.RFC3339))
	}
	return nil
}

func checkID(id string) error {
	if id == "" || len(id) > maxIDLength || strings.ContainsAny(id, " \t\r\n") {
		return fmt.Errorf("%w: missing or invalid ID", errInvalidRequest)
	}
	return nil
}

// refuse logs why a message was refused and shows a neutral page. The
// browser user does not need the details; the administrator finds them in
// the logs.
func (a *Adapter) refuse(w http.ResponseWriter, r *http.Request, issuer string, err error) {
	a.logger.WarnContext(r.Context(), "saml: request refused", "issuer", issuer, "error", err)
	a.renderMessage(w, r, http.StatusBadRequest, msgBadRequest)
}

// issuerOf reads the <saml:Issuer> of a protocol message.
func issuerOf(root *etree.Element) string {
	if el := childNS(root, "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer"); el != nil {
		return strings.TrimSpace(el.Text())
	}
	return ""
}

// unmarshalElement decodes an etree element with encoding/xml.
func unmarshalElement(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	b, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	if err := xml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", errBadMessage, err)
	}
	return nil
}

// nameIDFormatOf is the client's NameID format (persistent by default).
func nameIDFormatOf(app *domain.ClientApp) string {
	if app.NameIDFormat == "" {
		return domain.NameIDFormatPersistent
	}
	return app.NameIDFormat
}
