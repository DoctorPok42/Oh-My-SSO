package keymanager

import "context"

type KeyType string

const (
	KeyTypeRSA KeyType = "rsa"
	KeyTypeEC  KeyType = "ec"
)

type GeneratedKey struct {
	KMSKeyReference string
	PublicKeyPEM string
}

type KeyManager interface {
	GenerateKey(ctx context.Context, keyType KeyType) (*GeneratedKey, error)
	Sign(ctx context.Context, kmsKeyReference string, payload []byte) (signature []byte, err error)
}
