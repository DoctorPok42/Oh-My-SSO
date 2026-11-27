package service

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"sso.internal/sso/internal/i18n"
)

// normalizeClientKeys checks the keys of a private_key_jwt client: exactly
// one of a JWKS document and the https URL the client publishes it at. The
// JWKS is stored re-encoded.
//
// shortcut: RSA keys only (RS256): the OIDC library re-checks client
// assertions with RS256 alone. Allow PS256 / ES256 when FAPI (lot 12) needs
// them, together with the adapter's verification.
func normalizeClientKeys(jwks, jwksURI string) (string, string, error) {
	jwks, jwksURI = strings.TrimSpace(jwks), strings.TrimSpace(jwksURI)
	bad := func(t i18n.Text) error { return newTextError(ErrInvalidClientConfig, t) }
	switch {
	case (jwks == "") == (jwksURI == ""):
		return "", "", bad(i18n.M("admin.error.jwks_one", "private_key_jwt needs the client's public keys: a JWKS or a jwks_uri, not both"))
	case jwksURI != "":
		u, err := url.Parse(jwksURI)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(jwksURI, "#") {
			return "", "", bad(i18n.M("admin.error.jwks_uri_bad", "jwks_uri must be an https URL, without user info or fragment"))
		}
		return "", u.String(), nil
	}
	set, err := parseClientJWKS(jwks)
	if err != nil {
		return "", "", bad(i18n.M("admin.error.jwks_bad", "jwks: {error}", "error", err))
	}
	out, err := json.Marshal(set)
	if err != nil {
		return "", "", fmt.Errorf("encode jwks: %w", err)
	}
	return string(out), "", nil
}

// parseClientJWKS reads the JWKS an admin gives for a private_key_jwt client:
// 1 to 10 RSA public keys of 2048 bits or more, for signatures, with
// distinct "kid" when there are several. The OIDC adapter checks again the
// key it picks (a jwks_uri is read at sign-in, never here).
func parseClientJWKS(raw string) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		return nil, fmt.Errorf("not a valid JWK set: %w", err)
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxClientKeys {
		return nil, fmt.Errorf("between 1 and %d keys are expected", maxClientKeys)
	}
	kids := map[string]bool{}
	for i, k := range set.Keys {
		if err := checkClientKey(k); err != nil {
			return nil, fmt.Errorf("key %d: %w", i+1, err)
		}
		if len(set.Keys) > 1 && (k.KeyID == "" || kids[k.KeyID]) {
			return nil, errors.New("with several keys, each needs its own \"kid\"")
		}
		kids[k.KeyID] = true
	}
	return &set, nil
}

// checkClientKey: one key of a client's JWKS must be a public RSA key of 2048
// bits or more, for signatures with RS256.
func checkClientKey(k jose.JSONWebKey) error {
	if !k.IsPublic() {
		return errors.New("it is a private key: give the public key only")
	}
	pub, ok := k.Key.(*rsa.PublicKey)
	switch {
	case !ok:
		return errors.New("only RSA keys are supported (RS256)")
	case pub.N.BitLen() < 2048:
		return errors.New("an RSA key needs at least 2048 bits")
	case k.Use != "" && k.Use != "sig":
		return errors.New("\"use\" must be \"sig\"")
	case k.Algorithm != "" && k.Algorithm != string(jose.RS256):
		return errors.New("\"alg\" must be RS256")
	}
	return nil
}
