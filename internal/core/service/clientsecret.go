package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)


const clientSecretHashPrefix = "sha256:"

// MinClientSecretLength refuses short secrets supplied from the outside
// (config-as-code, `--secret`): 32 characters of a random string.
const MinClientSecretLength = 32

// NewClientSecret returns a new random secret and the hash to store.
func NewClientSecret() (secret, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HashClientSecret(secret)
}

// HashClientSecret returns the stored form of a client secret.
func HashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return clientSecretHashPrefix + hex.EncodeToString(sum[:])
}

// verifyClientSecret compares in constant time, so the response time does
// not tell an attacker how many characters were right.
func verifyClientSecret(secret, stored string) bool {
	if secret == "" || !strings.HasPrefix(stored, clientSecretHashPrefix) {
		return false
	}
	want := HashClientSecret(secret)
	return subtle.ConstantTimeCompare([]byte(want), []byte(stored)) == 1
}
