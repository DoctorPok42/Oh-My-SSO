package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 192 * 1024 // 64 MB
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

var errInvalidHashFormat = errors.New("service: invalid password hash format")

func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash password: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLength)
	return encodeArgon2id(argon2Memory, argon2Iterations, argon2Parallelism, salt, key), nil
}

func verifyPassword(password, encodedHash string) (bool, error) {
	h, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), h.salt, h.iterations, h.memory, h.parallelism, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

// argon2idHash is a parsed PHC string:
// $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<key>
type argon2idHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

// encodeArgon2id formats a PHC string (same format as HashPassword).
func encodeArgon2id(memory, iterations uint32, parallelism uint8, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parseArgon2idHash(encodedHash string) (*argon2idHash, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errInvalidHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, errInvalidHashFormat
	}

	h := &argon2idHash{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.iterations, &h.parallelism); err != nil {
		return nil, errInvalidHashFormat
	}

	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, errInvalidHashFormat
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, errInvalidHashFormat
	}
	return h, nil
}
