// Package jwks turns the public part of our signing keys into the JSON Web
// Key (JWK) format, and back.
//
// A JWK Set (RFC 7517 §5) is what a client downloads from
// /r/{realm}/.well-known/jwks.json to verify the signatures of the tokens we
// issue: it picks the key whose "kid" matches the "kid" of the token header.
//
// This package only uses the Go standard library and knows nothing about
// HTTP, the database or the KMS: it converts data, nothing else.
//
// References:
//   - RFC 7517 (JWK):                       https://www.rfc-editor.org/rfc/rfc7517
//   - RFC 7518 §6 (key parameters n/e/x/y): https://www.rfc-editor.org/rfc/rfc7518#section-6
//   - RFC 7518 §3.1 (RS256 / ES256):        https://www.rfc-editor.org/rfc/rfc7518#section-3.1
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"sso.internal/sso/internal/core/domain"
)

// MinRSABits is the smallest RSA modulus we accept to publish. RFC 7518
// §3.3 requires at least 2048 bits for RS256.
const MinRSABits = 2048

// JWK is one public key. Only public parameters exist in this struct: there
// is no field that could ever carry a private key ("d", "p", "q"...).
type JWK struct {
	Kty string `json:"kty"`           // key type: "RSA" or "EC"
	Kid string `json:"kid"`           // key id, copied into each token header
	Use string `json:"use"`           // "sig": this key verifies signatures
	Alg string `json:"alg"`           // "RS256" or "ES256"
	N   string `json:"n,omitempty"`   // RSA modulus (base64url, big-endian)
	E   string `json:"e,omitempty"`   // RSA public exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC curve: "P-256"
	X   string `json:"x,omitempty"`   // EC point X coordinate (32 bytes for P-256)
	Y   string `json:"y,omitempty"`   // EC point Y coordinate (32 bytes for P-256)
}

// Set is a JWK Set: {"keys": [...]}.
type Set struct {
	Keys []JWK `json:"keys"`
}

// Errors returned by the conversion. Callers can use errors.Is.
var (
	ErrNoPublicKey     = errors.New("jwks: signing key has no public key")
	ErrInvalidPEM      = errors.New("jwks: public key is not a valid PEM block")
	ErrUnsupportedKey  = errors.New("jwks: unsupported public key")
	ErrKeyTypeMismatch = errors.New("jwks: key_type does not match the public key")
)

// Algorithm returns the JOSE algorithm used with a key type. It is the single
// place where "RSA -> RS256" and "EC -> ES256" is decided: the future OIDC
// adapter must use the same function to fill the "alg" of the token header.
func Algorithm(t domain.SigningKeyType) (string, error) {
	switch t {
	case domain.SigningKeyRSA:
		return "RS256", nil
	case domain.SigningKeyEC:
		return "ES256", nil
	default:
		return "", fmt.Errorf("%w: key type %q", ErrUnsupportedKey, t)
	}
}

// FromSigningKey converts one stored key (its PEM public key) into a JWK.
func FromSigningKey(k *domain.SigningKey) (JWK, error) {
	if k.PublicKey == "" {
		return JWK{}, ErrNoPublicKey
	}
	block, _ := pem.Decode([]byte(k.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return JWK{}, ErrInvalidPEM
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, fmt.Errorf("%w: %v", ErrInvalidPEM, err)
	}
	return fromPublicKey(k.Kid, k.KeyType, pub)
}

func fromPublicKey(kid string, keyType domain.SigningKeyType, pub crypto.PublicKey) (JWK, error) {
	alg, err := Algorithm(keyType)
	if err != nil {
		return JWK{}, err
	}
	jwk := JWK{Kid: kid, Use: "sig", Alg: alg}

	switch p := pub.(type) {
	case *rsa.PublicKey:
		if keyType != domain.SigningKeyRSA {
			return JWK{}, fmt.Errorf("%w: stored as %s, PEM is RSA", ErrKeyTypeMismatch, keyType)
		}
		if p.N.BitLen() < MinRSABits {
			return JWK{}, fmt.Errorf("%w: RSA key of %d bits (minimum %d)", ErrUnsupportedKey, p.N.BitLen(), MinRSABits)
		}
		jwk.Kty = "RSA"
		// big.Int.Bytes() is already the minimal big-endian form RFC 7518
		// §6.3.1 asks for (no leading zero byte).
		jwk.N = b64(p.N.Bytes())
		jwk.E = b64(big.NewInt(int64(p.E)).Bytes()) // 65537 -> "AQAB"

	case *ecdsa.PublicKey:
		if keyType != domain.SigningKeyEC {
			return JWK{}, fmt.Errorf("%w: stored as %s, PEM is EC", ErrKeyTypeMismatch, keyType)
		}
		if p.Curve != elliptic.P256() {
			// ES256 means "ECDSA with P-256 and SHA-256": any other curve
			// would need another "alg" (ES384, ES512) that we do not sign with.
			return JWK{}, fmt.Errorf("%w: EC curve %s (only P-256)", ErrUnsupportedKey, p.Curve.Params().Name)
		}
		// Uncompressed point encoding: 0x04 || X (32 bytes) || Y (32 bytes).
		// Unlike big.Int.Bytes(), it keeps leading zero bytes, which RFC 7518
		// §6.2.1.2 requires ("MUST be the full size of a coordinate").
		raw, err := p.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("%w: %v", ErrUnsupportedKey, err)
		}
		const size = 32
		jwk.Kty = "EC"
		jwk.Crv = "P-256"
		jwk.X = b64(raw[1 : 1+size])
		jwk.Y = b64(raw[1+size:])

	default:
		return JWK{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	return jwk, nil
}

// SkippedKey explains why a key was left out of a Set.
type SkippedKey struct {
	Kid string
	Err error
}

// FromSigningKeys builds a Set, in the order of keys. A key that cannot be
// converted is left out (and reported in skipped) instead of failing the
// whole Set: one corrupt row must not stop clients from verifying tokens
// signed by the other, healthy keys.
//
// The returned Set always has a non-nil Keys slice, so it is encoded as
// {"keys":[]} and never {"keys":null}.
func FromSigningKeys(keys []*domain.SigningKey) (set Set, skipped []SkippedKey) {
	set.Keys = make([]JWK, 0, len(keys))
	for _, k := range keys {
		jwk, err := FromSigningKey(k)
		if err != nil {
			skipped = append(skipped, SkippedKey{Kid: k.Kid, Err: err})
			continue
		}
		set.Keys = append(set.Keys, jwk)
	}
	return set, skipped
}

// Find returns the key with that kid, the way a client looks up the key of a
// token it received.
func (s Set) Find(kid string) (JWK, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

// PublicKey rebuilds the Go public key from a JWK. It is what a client does
// after downloading the JWKS; we use it in tests to verify signatures exactly
// like a client would, from the published JSON only.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := unb64(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwks: decode n: %w", err)
		}
		e, err := unb64(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwks: decode e: %w", err)
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("%w: RSA exponent too large", ErrUnsupportedKey)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}, nil

	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("%w: EC curve %q", ErrUnsupportedKey, k.Crv)
		}
		x, err := unb64(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwks: decode x: %w", err)
		}
		y, err := unb64(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwks: decode y: %w", err)
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: P-256 coordinates must be 32 bytes", ErrUnsupportedKey)
		}
		// ParseUncompressedPublicKey also checks the point is on the curve.
		raw := append(append([]byte{0x04}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)

	default:
		return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKey, k.Kty)
	}
}

// base64url without "=" padding, as every JOSE value (RFC 7515 §2).
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
