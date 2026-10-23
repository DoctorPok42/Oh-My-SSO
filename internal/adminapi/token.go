package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/jwks"
)

// Verifying the admin console's access tokens.
//
// The admin console (Next.js) signs its admins in with OpenID Connect on the
// master realm, client "sso-admin", and sends the access token it received
// with every call: "Authorization: Bearer <token>" (RFC 6750). The token is
// a JWT signed by the master realm's key (RFC 9068 profile). This file checks
// the JWT itself; auth.go then checks the token's database row and the
// session behind it, so that a revoked session stops working at once even
// though the JWT is still unexpired.
//
// https://datatracker.ietf.org/doc/html/rfc6750
// https://datatracker.ietf.org/doc/html/rfc9068
// https://pkg.go.dev/github.com/go-jose/go-jose/v4

// allowedAlgs: what the IdP signs with. Anything else ("none", HS256 with
// the public key as secret...) is refused before any key is looked at.
var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// clockSkew tolerated on exp / nbf / iat.
const clockSkew = 30 * time.Second

var errInvalidToken = errors.New("invalid token")

// accessClaims: the claims we rely on.
type accessClaims struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  audience     `json:"aud"`
	Expiry    *json.Number `json:"exp"`
	NotBefore *json.Number `json:"nbf"`
	IssuedAt  *json.Number `json:"iat"`
	JTI       string       `json:"jti"`
	ClientID  string       `json:"client_id"`
	SessionID string       `json:"sid"`
}

// audience accepts "aud" as a string or an array of strings (RFC 7519 §4.1.3).
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// PublicKeySource lists a realm's published keys (core.IdentityCore).
type PublicKeySource interface {
	PublicKeys(ctx context.Context, realmID string, purpose domain.SigningKeyPurpose) ([]*domain.SigningKey, error)
}

// tokenVerifier checks signature and claims of admin access tokens.
type tokenVerifier struct {
	keys     PublicKeySource
	issuer   string // PUBLIC_URL/r/master
	audience string // "sso-admin"
	now      func() time.Time

	mu      sync.Mutex
	cached  jwks.Set
	fetched time.Time
}

// keyCacheTTL: keys are re-read at most this often, and at once when a
// token names a kid we do not know (a rotation just happened).
const keyCacheTTL = time.Minute

func (v *tokenVerifier) keySet(ctx context.Context, realmID string, refresh bool) (jwks.Set, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !refresh && v.now().Sub(v.fetched) < keyCacheTTL && len(v.cached.Keys) > 0 {
		return v.cached, nil
	}
	keys, err := v.keys.PublicKeys(ctx, realmID, domain.SigningKeyPurposeJWT)
	if err != nil {
		return jwks.Set{}, err
	}
	set, _ := jwks.FromSigningKeys(keys)
	v.cached, v.fetched = set, v.now()
	return set, nil
}

// verify returns the claims of a valid token, or errInvalidToken.
func (v *tokenVerifier) verify(ctx context.Context, realmID, raw string) (*accessClaims, error) {
	jws, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errInvalidToken
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, errInvalidToken
	}
	set, err := v.keySet(ctx, realmID, false)
	if err != nil {
		return nil, fmt.Errorf("load signing keys: %w", err)
	}
	key, ok := set.Find(kid)
	if !ok {
		if set, err = v.keySet(ctx, realmID, true); err != nil {
			return nil, fmt.Errorf("load signing keys: %w", err)
		}
		if key, ok = set.Find(kid); !ok {
			return nil, errInvalidToken
		}
	}
	// The algorithm must be the key's own: an RSA key never verifies an
	// "ES256" header, and the reverse.
	if key.Alg != "" && key.Alg != jws.Signatures[0].Header.Algorithm {
		return nil, errInvalidToken
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, errInvalidToken
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, errInvalidToken
	}

	var c accessClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errInvalidToken
	}
	now := v.now()
	if c.Issuer != v.issuer || !slices.Contains(c.Audience, v.audience) {
		return nil, errInvalidToken
	}
	if c.ClientID != "" && c.ClientID != v.audience {
		return nil, errInvalidToken
	}
	exp, ok := unix(c.Expiry)
	if !ok || !now.Before(exp.Add(clockSkew)) {
		return nil, errInvalidToken
	}
	if nbf, ok := unix(c.NotBefore); ok && now.Add(clockSkew).Before(nbf) {
		return nil, errInvalidToken
	}
	if iat, ok := unix(c.IssuedAt); ok && now.Add(clockSkew).Before(iat) {
		return nil, errInvalidToken
	}
	if c.JTI == "" || c.SessionID == "" {
		return nil, errInvalidToken
	}
	return &c, nil
}

func unix(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}
