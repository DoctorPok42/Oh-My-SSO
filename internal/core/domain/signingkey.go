package domain

import "time"

type SigningKeyType string

const (
	SigningKeyRSA SigningKeyType = "RSA"
	SigningKeyEC  SigningKeyType = "EC"
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
}
