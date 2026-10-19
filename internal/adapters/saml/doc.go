// Package saml is the SAML 2.0 adapter (Step 11): it turns the neutral
// primitives of core.IdentityCore into the SAML 2.0 Web Browser SSO and
// Single Logout profiles, playing the Identity Provider (IdP) role.
//
// It uses github.com/crewjam/saml for the SAML XML types and
// github.com/russellhaering/goxmldsig for XML signatures (never written by
// hand). crewjam's ready-made IdP handler is NOT used: it cannot sign with a
// KMS-backed key per realm, checks no request signature, keeps no replay
// cache and has no logout. The flow below is ours, built from its types.
//
// Endpoints, per realm (IdP entity ID = PUBLIC_URL + "/r/{realm}/saml/metadata"):
//
//	GET      /r/{realm}/saml/metadata     IdP metadata: entity ID, endpoints, signing certificates
//	GET/POST /r/{realm}/saml/sso          receives an AuthnRequest (HTTP-Redirect or HTTP-POST binding)
//	GET      /r/{realm}/saml/login        sign-in page (password, MFA, passkey), then the assertion
//	GET/POST /r/{realm}/saml/slo          Single Logout: LogoutRequest from a service provider,
//	                                      LogoutResponse while logging out the others
//	GET      /r/{realm}/saml/logged-out   "you are signed out"
//
// Rules of this package, checked by `make check-adapter-deps`: it only talks
// to the rest of the IdP through core.IdentityCore and oidcstore.Store
// (short-lived state, under "saml:" keys). It never imports Ent, Valkey, the
// KeyManager or the HTTP server package.
//
// Decisions of Step 11:
//   - service-provider-initiated SSO only (no unsolicited responses yet);
//   - a service provider with a registered certificate must sign every
//     request it sends; one without a certificate can log users in (the
//     response only ever goes to its registered ACS URL) but cannot send a
//     LogoutRequest;
//   - logout propagates to the other service providers of the session
//     through the browser, one HTTP-Redirect round trip each.
package saml
