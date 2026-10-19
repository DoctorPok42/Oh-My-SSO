package domain

import "time"

type SigningKeyType string

const (
	SigningKeyRSA SigningKeyType = "RSA"
	SigningKeyEC  SigningKeyType = "EC"
	// SigningKeyAES: symmetric key, envelope_encryption purpose only.
	SigningKeyAES SigningKeyType = "AES"
)

type SigningKeyPurpose string

const (
	SigningKeyPurposeJWT             SigningKeyPurpose = "jwt_signing"
	SigningKeyPurposeSAMLSigning     SigningKeyPurpose = "saml_signing"
	SigningKeyPurposeSAMLEncryption  SigningKeyPurpose = "saml_encryption"
	SigningKeyPurposeEnvelopeEncrypt SigningKeyPurpose = "envelope_encryption"
)

type SigningKeyStatus string

const (
	// SigningKeyPending (Step 11, saml_signing only): published in the SAML
	// metadata, but does not sign yet. See KeyRotationService.Activate.
	SigningKeyPending  SigningKeyStatus = "pending"
	SigningKeyActive   SigningKeyStatus = "active"
	SigningKeyRotating SigningKeyStatus = "rotating"
	SigningKeyRetired  SigningKeyStatus = "retired"
)

type SigningKey struct {
	ID              string
	RealmID         string
	KeyType         SigningKeyType
	Purpose         SigningKeyPurpose
	KMSKeyReference string
	KMSBackend      string
	PublicKey       string
	Kid             string
	Status          SigningKeyStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
	RetiredAt       time.Time
	// RetireAfter is the end of the grace period of a "rotating" key (zero
	// for an "active" key). After it, the key leaves the JWKS.
	RetireAfter time.Time
	// Certificate is the self-signed X.509 certificate of the key, PEM
	// encoded (saml_signing keys, Step 11). Empty for JWT keys.
	Certificate string
}
