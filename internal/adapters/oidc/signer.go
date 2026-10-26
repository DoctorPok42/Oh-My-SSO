package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


func algFor(t domain.SigningKeyType) (jose.SignatureAlgorithm, error) {
	switch t {
	case domain.SigningKeyRSA:
		return jose.RS256, nil
	case domain.SigningKeyEC:
		return jose.ES256, nil
	}
	return "", fmt.Errorf("oidc: unsupported signing key type %q", t)
}

// signingKey implements op.SigningKey for the realm's current key.
type signingKey struct {
	kid string
	alg jose.SignatureAlgorithm
	key *kmsSigner
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *signingKey) Key() any                                    { return k.key }
func (k *signingKey) ID() string                                  { return k.kid }

// kmsSigner is the jose.OpaqueSigner. It keeps the request context: go-jose's
// SignPayload has no context parameter, but the KMS call needs one (deadline,
// cancellation when the client goes away).
type kmsSigner struct {
	ctx    context.Context
	signer core.Signer
	pub    crypto.PublicKey
	alg    jose.SignatureAlgorithm
}

var _ jose.OpaqueSigner = (*kmsSigner)(nil)

func (s *kmsSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: s.pub, KeyID: s.signer.KeyID(), Algorithm: string(s.alg), Use: "sig"}
}

func (s *kmsSigner) Algs() []jose.SignatureAlgorithm { return []jose.SignatureAlgorithm{s.alg} }

func (s *kmsSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != s.alg {
		return nil, fmt.Errorf("oidc: key %s signs %s, not %s", s.signer.KeyID(), s.alg, alg)
	}
	// core.Signer hashes with SHA-256, then signs: PKCS#1 v1.5 for RSA
	// (= RS256), ECDSA P-256 for EC.
	sig, err := s.signer.Sign(s.ctx, payload)
	if err != nil {
		return nil, err
	}
	if s.alg == jose.ES256 {
		// The KMS returns ECDSA signatures ASN.1 DER encoded; JWS wants the
		// raw 64 bytes r||s (RFC 7518, section 3.4).
		return derToRawECDSA(sig, 32)
	}
	return sig, nil
}

// derToRawECDSA converts an ASN.1 DER ECDSA signature to r||s, each
// left-padded to size bytes.
func derToRawECDSA(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("oidc: decode ECDSA signature: %w", err)
	}
	if len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("oidc: malformed ECDSA signature")
	}
	if sig.R.BitLen() > size*8 || sig.S.BitLen() > size*8 {
		return nil, errors.New("oidc: ECDSA signature too large for the curve")
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

func parsePublicKeyPEM(p string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("oidc: public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("oidc: unsupported public key %T", pub)
}

// publicKey implements op.Key (what KeySet returns to the library, which
// uses it to verify our own tokens: access tokens at /userinfo, the
// id_token_hint at /logout).
type publicKey struct {
	kid string
	alg jose.SignatureAlgorithm
	key crypto.PublicKey
}

var _ op.Key = (*publicKey)(nil)

func (k *publicKey) ID() string                         { return k.kid }
func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return k.alg }
func (k *publicKey) Use() string                        { return "sig" }
func (k *publicKey) Key() any                           { return k.key }
