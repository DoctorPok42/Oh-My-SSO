package saml

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"time"

	"github.com/beevik/etree"
	samllib "github.com/crewjam/saml"

	"sso.internal/sso/internal/adapters/loginui"
	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

// Building the <samlp:Response> sent to the service provider's ACS
// (SAML Core §2 and §3.2, Profiles §4.1.4.2).

const (
	statusRequestDenied       = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	statusNoPassive           = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	statusInvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	statusAuthnFailed         = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	statusUnsupportedBinding  = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
	statusPartialLogout       = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	nameIDFormatEntity = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	cmBearer           = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

	// AuthnContextClassRef values: how the user authenticated.
	acPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	acUnspecified                = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	// REFEDS MFA profile: the de facto value for "multi-factor" (SAML 2.0
	// itself has no class for it). https://refeds.org/profile/mfa
	acREFEDSMFA = "https://refeds.org/profile/mfa"

	// notBeforeSkew: the assertion is valid from a little before now, for
	// service providers whose clock is slightly ahead.
	notBeforeSkew = time.Minute
)

// assertionInput is everything one assertion is made of.
type assertionInput struct {
	realm        Realm
	app          *domain.ClientApp
	req          *pendingRequest
	as           *core.IdentityAssertion
	sessionEnd   time.Time // SessionNotOnOrAfter: end of the IdP session
	nameID       string
	nameIDFormat string
	sessionIndex string
}

// assertionResponse builds and signs a successful response. The assertion
// is always signed; the response too when the client asks for it.
func (a *Adapter) assertionResponse(ctx context.Context, key *signingKey, in assertionInput) ([]byte, error) {
	now := a.now().UTC()
	issuer := a.entityID(in.realm)
	notOnOrAfter := in.as.ExpiresAt.UTC()
	sessionEnd := in.sessionEnd.UTC()

	assertion := &samllib.Assertion{
		ID:           newID(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       samllib.Issuer{Format: nameIDFormatEntity, Value: issuer},
		Subject: &samllib.Subject{
			NameID: &samllib.NameID{
				Format:          in.nameIDFormat,
				NameQualifier:   issuer,
				SPNameQualifier: in.app.EntityID,
				Value:           in.nameID,
			},
			SubjectConfirmations: []samllib.SubjectConfirmation{{
				Method: cmBearer,
				SubjectConfirmationData: &samllib.SubjectConfirmationData{
					InResponseTo: in.req.RequestID,
					NotOnOrAfter: notOnOrAfter,
					Recipient:    in.req.ACSURL,
				},
			}},
		},
		Conditions: &samllib.Conditions{
			NotBefore:    now.Add(-notBeforeSkew),
			NotOnOrAfter: notOnOrAfter,
			AudienceRestrictions: []samllib.AudienceRestriction{{
				Audience: samllib.Audience{Value: in.as.Audience},
			}},
		},
		AuthnStatements: []samllib.AuthnStatement{{
			AuthnInstant:        in.as.AuthTime.UTC(),
			SessionIndex:        in.sessionIndex,
			SessionNotOnOrAfter: &sessionEnd,
			AuthnContext: samllib.AuthnContext{
				AuthnContextClassRef: &samllib.AuthnContextClassRef{Value: authnContextClass(in.as)},
			},
		}},
	}
	if attrs := buildAttributes(in.as, in.app, a.logger); len(attrs) > 0 {
		assertion.AttributeStatements = []samllib.AttributeStatement{{Attributes: attrs}}
	}

	sig, err := key.signature(ctx, assertion.Element())
	if err != nil {
		return nil, wrap(err, "sign assertion")
	}
	assertion.Signature = sig

	resp := a.newResponse(in.realm, in.req, now)
	resp.Assertion = assertion
	return a.serializeResponse(ctx, key, resp, in.app.WantResponseSigned)
}

// errorResponse builds a signed response without assertion (SAML Core
// §3.2.2.2 status codes). top is Requester or Responder.
func (a *Adapter) errorResponse(ctx context.Context, key *signingKey, realm Realm, req *pendingRequest, top, second, text string) ([]byte, error) {
	resp := a.newResponse(realm, req, a.now().UTC())
	resp.Status.StatusCode.Value = top
	if second != "" {
		resp.Status.StatusCode.StatusCode = &samllib.StatusCode{Value: second}
	}
	if text != "" {
		resp.Status.StatusMessage = &samllib.StatusMessage{Value: text}
	}
	// No assertion to carry a signature: always sign the response itself.
	return a.serializeResponse(ctx, key, resp, true)
}

func (a *Adapter) newResponse(realm Realm, req *pendingRequest, now time.Time) *samllib.Response {
	return &samllib.Response{
		ID:           newID(),
		InResponseTo: req.RequestID,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  req.ACSURL,
		Issuer:       &samllib.Issuer{Format: nameIDFormatEntity, Value: a.entityID(realm)},
		Status:       samllib.Status{StatusCode: samllib.StatusCode{Value: samllib.StatusSuccess}},
	}
}

func (a *Adapter) serializeResponse(ctx context.Context, key *signingKey, resp *samllib.Response, sign bool) ([]byte, error) {
	if sign {
		sig, err := key.signature(ctx, resp.Element())
		if err != nil {
			return nil, wrap(err, "sign response")
		}
		resp.Signature = sig
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(resp.Element())
	return doc.WriteToBytes()
}

// postToACS hands a response to the browser, which POSTs it to the ACS.
func (a *Adapter) postToACS(w http.ResponseWriter, r *http.Request, req *pendingRequest, xmlResp []byte) {
	realm, _ := realmFrom(r.Context())
	fields := []loginui.Field{{Name: paramResponse, Value: base64.StdEncoding.EncodeToString(xmlResp)}}
	if req.RelayState != "" {
		fields = append(fields, loginui.Field{Name: "RelayState", Value: req.RelayState})
	}
	err := a.pages.RenderAutoPost(w, loginui.AutoPost{
		Action: req.ACSURL,
		Fields: fields,
		Assets: assets(realm),
		Title:  "Signing you in…",
		Text:   "You are being sent back to the application.",
	})
	if err != nil {
		a.logger.ErrorContext(r.Context(), "saml: render auto-post form", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
	}
}

// sendError posts an error response to the service provider and forgets
// the request. When even that is impossible (no signing key), a page.
func (a *Adapter) sendError(w http.ResponseWriter, r *http.Request, req *pendingRequest, top, second, text string) {
	ctx := r.Context()
	realm, _ := realmFrom(ctx)
	if err := a.store.Delete(ctx, pendingKey(req.ID)); err != nil {
		a.logger.WarnContext(ctx, "saml: delete pending request", "error", err)
	}
	key, err := a.signingKey(ctx, realm)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: no key to sign an error response", "error", err)
		a.renderMessage(w, r, http.StatusServiceUnavailable, msgNoKey)
		return
	}
	out, err := a.errorResponse(ctx, key, realm, req, top, second, text)
	if err != nil {
		a.logger.ErrorContext(ctx, "saml: build error response", "error", err)
		a.renderMessage(w, r, http.StatusInternalServerError, msgBadRequest)
		return
	}
	a.postToACS(w, r, req, out)
}

func authnContextClass(as *core.IdentityAssertion) string {
	switch {
	case as.MFAVerified:
		return acREFEDSMFA
	case slices.Contains(as.AuthMethods, domain.AuthMethodPassword):
		return acPasswordProtectedTransport
	default:
		return acUnspecified
	}
}
