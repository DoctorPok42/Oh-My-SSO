package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters of new password hashes: the second recommended
// option of RFC 9106 (64 MiB of memory, 3 passes, 4 lanes, 16-byte salt,
// 32-byte key), for servers that cannot spend 2 GiB on one hash.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-4
//
// Every hash keeps its own parameters ("$argon2id$v=19$m=65536,t=3,p=4$..."),
// so changing these values never breaks an existing password: it is still
// checked with the parameters it was made with, and re-hashed with these
// ones at its next successful sign-in (needsRehash, AuthService).
const (
	argon2Memory      = 64 * 1024 // in KiB: 64 MiB
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2SaltLength  = 16
	argon2KeyLength   = 32

	// PasswordHashMemoryMiB is the RAM one password hash holds while it runs.
	PasswordHashMemoryMiB = argon2Memory / 1024
)

// DefaultPasswordHashConcurrency: how many Argon2id password computations
// may run at the same time. Each one holds its memory parameter (64 MiB)
// while it runs: without a limit, 50 sign-in attempts at once, even with
// wrong passwords or unknown usernames, would need 3.2 GiB and could make
// the server run out of memory. The other attempts wait for a free slot.
// 4 slots = 256 MiB at most. PASSWORD_HASH_CONCURRENCY changes it.
const DefaultPasswordHashConcurrency = 4

// hashSlots is a counting semaphore: a buffered channel of N slots. Taking
// a slot is sending into it (blocks while it is full), giving it back is
// receiving from it. https://go.dev/tour/concurrency/3
var hashSlots atomic.Pointer[chan struct{}]

func init() { SetPasswordHashConcurrency(DefaultPasswordHashConcurrency) }

// SetPasswordHashConcurrency sets how many password hashes may be computed
// at the same time (at least 1). Call it at startup.
func SetPasswordHashConcurrency(n int) {
	if n < 1 {
		n = 1
	}
	slots := make(chan struct{}, n)
	hashSlots.Store(&slots)
}

var errInvalidHashFormat = errors.New("service: invalid password hash format")

// argon2idKey computes one Argon2id key once a slot is free. It gives up
// with ctx's error if ctx ends first: the client went away while waiting.
func argon2idKey(ctx context.Context, password, salt []byte, iterations, memory uint32, parallelism uint8, keyLen uint32) ([]byte, error) {
	slots := *hashSlots.Load()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-slots }()
	return argon2.IDKey(password, salt, iterations, memory, parallelism, keyLen), nil
}

// HashPassword hashes a new password with Argon2id. Prefer
// HashPasswordContext when a request is waiting for the result.
func HashPassword(password string) (string, error) {
	return HashPasswordContext(context.Background(), password)
}

// HashPasswordContext is HashPassword, giving up if ctx ends while waiting
// for a free slot (see DefaultPasswordHashConcurrency).
func HashPasswordContext(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash password: generate salt: %w", err)
	}

	key, err := argon2idKey(ctx, []byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLength)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return encodeArgon2id(argon2Memory, argon2Iterations, argon2Parallelism, salt, key), nil
}

func verifyPassword(ctx context.Context, password, encodedHash string) (bool, error) {
	h, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false, err
	}
	got, err := argon2idKey(ctx, []byte(password), h.salt, h.iterations, h.memory, h.parallelism, uint32(len(h.key)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

// needsRehash reports whether a stored hash was made with other parameters
// than today's (by an older version), so that the password should be
// hashed again once the user proves it. An unreadable hash returns false:
// it cannot be verified anyway.
func needsRehash(encodedHash string) bool {
	h, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false
	}
	return h.memory != argon2Memory ||
		h.iterations != argon2Iterations ||
		h.parallelism != argon2Parallelism ||
		len(h.salt) != argon2SaltLength ||
		len(h.key) != argon2KeyLength
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
