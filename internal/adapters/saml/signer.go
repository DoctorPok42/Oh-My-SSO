package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
)


var errNoSigningKey = errors.New("saml: no active SAML signing key in this realm (idp keys rotate --purpose saml_signing)")

// signingKey is the realm's active SAML key, for one request.
type signingKey struct {
	signer core.DigestSigner
	cert   *x509.Certificate
}

func (a *Adapter) signingKey(ctx context.Context, realm Realm) (*signingKey, error) {
	s, err := a.core.Signer(ctx, realm.ID, domain.SigningKeyPurposeSAMLSigning)
	if errors.Is(err, core.ErrNoActiveSigningKey) {
		return nil, errNoSigningKey
	}
	if err != nil {
		return nil, err
	}
	ds, ok := s.(core.DigestSigner)
	if !ok {
		return nil, errors.New("saml: the core signer cannot sign digests")
	}
	if ds.KeyType() != domain.SigningKeyRSA {
		return nil, fmt.Errorf("saml: signing key %s is %s, SAML needs RSA", ds.KeyID(), ds.KeyType())
	}
	cert, err := parseCertificatePEM(ds.CertificatePEM())
	if err != nil {
		return nil, fmt.Errorf("saml: signing key %s: %w", ds.KeyID(), err)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("saml: signing key %s: certificate is not RSA", ds.KeyID())
	}
	return &signingKey{signer: ds, cert: cert}, nil
}

// xmlContext is a goxmldsig signing context: RSA-SHA256, exclusive XML
// canonicalization (what SAML expects), our certificate in <KeyInfo>.
func (k *signingKey) xmlContext(ctx context.Context) (*dsig.SigningContext, error) {
	sc, err := dsig.NewSigningContext(&kmsSigner{ctx: ctx, key: k}, [][]byte{k.cert.Raw})
	if err != nil {
		return nil, err
	}
	// An empty prefix list: some implementations do not support others.
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	return sc, nil
}

// signature signs el (enveloped signature, referencing el's ID attribute)
// and returns the <ds:Signature> element. The caller puts it in its place:
// the SAML schema wants it right after <Issuer>.
func (k *signingKey) signature(ctx context.Context, el *etree.Element) (*etree.Element, error) {
	sc, err := k.xmlContext(ctx)
	if err != nil {
		return nil, err
	}
	signed, err := sc.SignEnveloped(el)
	if err != nil {
		return nil, err
	}
	children := signed.ChildElements()
	sig := children[len(children)-1]
	if sig.Tag != "Signature" {
		return nil, errors.New("saml: signature element not found after signing")
	}
	return sig, nil
}

// signQuery signs the HTTP-Redirect binding string and returns the base64
// value of the Signature parameter.
func (k *signingKey) signQuery(ctx context.Context, signed string) (string, error) {
	digest := sha256.Sum256([]byte(signed))
	sig, err := k.signer.SignDigest(ctx, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// kmsSigner is the crypto.Signer given to goxmldsig.
type kmsSigner struct {
	ctx context.Context
	key *signingKey
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.key.cert.PublicKey }

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("saml: only SHA-256 signatures are produced, got %v", opts.HashFunc())
	}
	return s.key.signer.SignDigest(s.ctx, digest)
}

func parseCertificatePEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
