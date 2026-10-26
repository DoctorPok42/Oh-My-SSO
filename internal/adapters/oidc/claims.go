package oidc

import (
	"log/slog"
	"slices"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)

type location string

const (
	locIDToken     location = "id_token"
	locAccessToken location = "access_token"
	locUserinfo    location = "userinfo"
)

// reservedClaims can never be produced by a claim mapper nor be the source
// or target of an attribute_mappings rename: they carry the security of the
// token (who, for whom, until when, how). Letting an admin map "email" onto
// "sub" would let any user with a chosen e-mail impersonate another.
var reservedClaims = []string{
	"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "auth_time", "nonce",
	"acr", "amr", "azp", "sid", "at_hash", "c_hash", "s_hash", "client_id",
	"scope", "cnf", "act", "may_act", "typ", "token_type", "events",
	"entitlements",
}

func isReserved(name string) bool { return name == "" || slices.Contains(reservedClaims, name) }

// Standard claims of the "profile" scope (OIDC Core, section 5.4). They are
// read from User.Profile when a key of the same name exists.
var profileClaims = []string{
	"name", "given_name", "family_name", "middle_name", "nickname", "profile",
	"picture", "website", "gender", "birthdate", "zoneinfo", "locale",
}

// claimMapper is one entry of ClientScope.claim_mappers:
//
//	{"source_attribute": "groups", "claim_name": "groups",
//	 "token_location": ["id_token", "userinfo"]}
//
// token_location may be a string or a list; missing means id_token +
// userinfo (the identity claims, not the API access token).
type claimMapper struct {
	source    string
	claim     string
	locations []location
}

func parseClaimMapper(raw map[string]interface{}) (claimMapper, bool) {
	src, _ := raw["source_attribute"].(string)
	name, _ := raw["claim_name"].(string)
	if src == "" || name == "" {
		return claimMapper{}, false
	}
	m := claimMapper{source: src, claim: name}
	switch v := raw["token_location"].(type) {
	case string:
		m.locations = []location{location(v)}
	case []interface{}:
		for _, x := range v {
			if s, ok := x.(string); ok {
				m.locations = append(m.locations, location(s))
			}
		}
	case []string:
		for _, s := range v {
			m.locations = append(m.locations, location(s))
		}
	}
	if len(m.locations) == 0 {
		m.locations = []location{locIDToken, locUserinfo}
	}
	return m, true
}

// buildClaims decides what leaves the IdP for one token or response, in
// three steps:
//
//  1. standard scopes the request was granted ("profile", "email"), for the
//     id_token and /userinfo only;
//  2. the claim mappers of the effective ClientScopes (RBAC already decided
//     which scopes the user has, and the client asked for them);
//  3. the client's attribute_mappings, which can only RENAME what steps 1-2
//     produced ({"email": "mail"}), never add data.
//
// UserAttributes that no step selects never leave (minimal disclosure).
func buildClaims(as *core.IdentityAssertion, pc *core.ProtocolClient, granted []string, loc location, log *slog.Logger) map[string]any {
	out := map[string]any{}
	attrs := as.UserAttributes

	if loc != locAccessToken {
		if slices.Contains(granted, scopeProfile) {
			if v, ok := attrs["username"]; ok {
				out["preferred_username"] = v
			}
			for _, c := range profileClaims {
				if v, ok := attrs["profile."+c]; ok {
					out[c] = v
				}
			}
			if v, ok := attrs["updated_at"]; ok {
				out["updated_at"] = v
			}
		}
		if slices.Contains(granted, scopeEmail) {
			if v, ok := attrs["email"]; ok {
				out["email"] = v
				// Only claim "verified" when the profile says so: an unknown
				// status must not be reported as verified.
				if verified, ok := attrs["profile.email_verified"].(bool); ok {
					out["email_verified"] = verified
				}
			}
		}
	}

	for _, cs := range as.Scopes {
		if cs.Protocol == domain.ClientScopeProtocolSAML2 {
			continue
		}
		for _, raw := range cs.ClaimMappers {
			m, ok := parseClaimMapper(raw)
			if !ok || !slices.Contains(m.locations, loc) {
				continue
			}
			if isReserved(m.claim) {
				log.Warn("oidc: claim mapper targets a reserved claim, ignored",
					"client_scope", cs.Name, "claim", m.claim)
				continue
			}
			if v, ok := attrs[m.source]; ok {
				out[m.claim] = v
			}
		}
	}

	if pc != nil {
		applyRenames(out, pc.App.AttributeMappings, pc.App.ClientID, log)
	}
	return out
}

// applyRenames applies Client.attribute_mappings ({"from": "to"}), in a
// stable order. A rename is skipped (and logged) when it touches a reserved
// claim or would overwrite another claim.
func applyRenames(claims map[string]any, mappings map[string]interface{}, clientID string, log *slog.Logger) {
	froms := make([]string, 0, len(mappings))
	for from := range mappings {
		froms = append(froms, from)
	}
	slices.Sort(froms)

	for _, from := range froms {
		to, _ := mappings[from].(string)
		if to == "" || to == from {
			continue
		}
		if isReserved(from) || isReserved(to) {
			log.Warn("oidc: attribute_mappings touches a reserved claim, ignored",
				"client_id", clientID, "from", from, "to", to)
			continue
		}
		v, ok := claims[from]
		if !ok {
			continue
		}
		if _, taken := claims[to]; taken {
			log.Warn("oidc: attribute_mappings would overwrite a claim, ignored",
				"client_id", clientID, "from", from, "to", to)
			continue
		}
		delete(claims, from)
		claims[to] = v
	}
}
