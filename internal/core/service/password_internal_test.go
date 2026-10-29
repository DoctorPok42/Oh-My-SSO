package service

// White-box tests of the Argon2id helpers: parameters, old hashes, the
// limit on hashes computed at the same time.

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

func TestHashPassword_UsesRFC9106Parameters(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	require.Contains(t, encoded, "$argon2id$v=19$m=65536,t=3,p=4$")

	h, err := parseArgon2idHash(encoded)
	require.NoError(t, err)
	require.Equal(t, uint32(64*1024), h.memory, "64 MiB, in KiB")
	require.Len(t, h.salt, 16)
	require.Len(t, h.key, 32)
	require.False(t, needsRehash(encoded), "a new hash is up to date")

	ok, err := verifyPassword(context.Background(), "correct horse battery staple", encoded)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = verifyPassword(context.Background(), "wrong", encoded)
	require.NoError(t, err)
	require.False(t, ok)
}

// oldHash builds a hash the way an older version would have, with other
// (cheap, for the test) parameters.
func oldHash(t *testing.T, password string, memory, iterations uint32, parallelism uint8) string {
	t.Helper()
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return encodeArgon2id(memory, iterations, parallelism, salt, key)
}

func TestVerifyPassword_OldParametersStillWork(t *testing.T) {
	encoded := oldHash(t, "s3cret-password", 19*1024, 2, 1)
	ok, err := verifyPassword(context.Background(), "s3cret-password", encoded)
	require.NoError(t, err)
	require.True(t, ok, "each hash is checked with its own parameters")
	require.True(t, needsRehash(encoded))
}

func TestNeedsRehash(t *testing.T) {
	// The parameters of the previous versions (192 MiB): the key bytes do
	// not matter, only the parameters are read.
	key := make([]byte, 32)
	salt := make([]byte, 16)
	require.True(t, needsRehash(encodeArgon2id(192*1024, 3, 4, salt, key)))
	require.True(t, needsRehash(encodeArgon2id(argon2Memory, 2, argon2Parallelism, salt, key)))
	require.True(t, needsRehash(encodeArgon2id(argon2Memory, argon2Iterations, 1, salt, key)))
	require.True(t, needsRehash(encodeArgon2id(argon2Memory, argon2Iterations, argon2Parallelism, salt, key[:16])))
	require.False(t, needsRehash(encodeArgon2id(argon2Memory, argon2Iterations, argon2Parallelism, salt, key)))

	for _, bad := range []string{"", "plain-text", "$2a$10$bcrypthash", "$argon2id$v=19$m=x$a$b"} {
		require.False(t, needsRehash(bad), "an unreadable hash is never re-hashed: %q", bad)
	}
}

// withHashConcurrency sets the limit for one test.
func withHashConcurrency(t *testing.T, n int) {
	t.Helper()
	SetPasswordHashConcurrency(n)
	t.Cleanup(func() { SetPasswordHashConcurrency(DefaultPasswordHashConcurrency) })
}

func TestArgon2idKey_WaitsWhileEverySlotIsTaken(t *testing.T) {
	withHashConcurrency(t, 2)
	slots := *hashSlots.Load()
	slots <- struct{}{}
	slots <- struct{}{} // two other sign-ins hold both slots

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := HashPasswordContext(ctx, "whatever-password")
	require.ErrorIs(t, err, context.DeadlineExceeded, "it waited for a slot, then the client went away")

	ok, err := verifyPassword(ctx, "whatever-password", oldHash(t, "x", 8*1024, 1, 1))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, ok)

	<-slots // one of the other sign-ins ended
	_, err = HashPasswordContext(context.Background(), "whatever-password")
	require.NoError(t, err)
	require.Len(t, slots, 1, "the slot used by the hash was given back")
}

func TestSetPasswordHashConcurrency_AtLeastOne(t *testing.T) {
	withHashConcurrency(t, 0)
	require.Equal(t, 1, cap(*hashSlots.Load()))
}
