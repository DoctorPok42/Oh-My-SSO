// Package oidc is the OpenID Connect adapter (Step 10): it turns the neutral
// primitives of core.IdentityCore into the OIDC protocol, using
// github.com/zitadel/oidc/v3 (package op) for the protocol mechanics.
//
// Endpoints, per realm (issuer = PUBLIC_URL + "/r/{realm}"):
//
//	GET      /r/{realm}/.well-known/openid-configuration  discovery (OIDC Discovery 1.0)
//	GET      /r/{realm}/.well-known/jwks.json              public keys (Step 8, not served here)
//	GET/POST /r/{realm}/oidc/authorize                     start a login (authorization code + PKCE)
//	GET      /r/{realm}/oidc/login                         login page (password, MFA, passkey)
//	GET      /r/{realm}/oidc/authorize/callback            issues the code once the user is in
//	POST     /r/{realm}/oidc/token                         code -> tokens, refresh -> tokens
//	GET/POST /r/{realm}/oidc/userinfo                      claims for an access token
//	POST     /r/{realm}/oidc/revoke                        RFC 7009
//	POST     /r/{realm}/oidc/introspect                    RFC 7662 (confidential clients)
//	GET      /r/{realm}/oidc/logout                        RP-initiated logout (needs id_token_hint)
//
// Rules of this package, checked by `make check-adapter-deps`: it only talks
// to the rest of the IdP through core.IdentityCore (users, sessions, RBAC,
// MFA, tokens, keys) and oidcstore.Store (short-lived login state). It never
// imports Ent, Valkey, the KeyManager or the HTTP server package.
package oidc
