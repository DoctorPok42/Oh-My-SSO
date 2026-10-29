package service_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

const rehashPassword = "correct-horse-battery-staple"

// legacyHash is a password hash with other Argon2id parameters than today's,
// as an older version would have stored it (cheap ones, for the test).
func legacyHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	key := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, 19*1024, 2, 1,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func newRehashFixture(t *testing.T, hash string) (*memUsers, *service.AuthService) {
	t.Helper()
	users := newMemUsers(&domain.User{
		ID: "u-erin", RealmID: resetRealm, Username: "erin", Email: "erin@example.test",
		PasswordHash: hash, Status: domain.UserActive,
	})
	return users, service.NewAuthService(users, &fakeLoginAttemptRepo{})
}

func signIn(auth *service.AuthService, password string) error {
	_, err := auth.AuthenticateLocal(context.Background(), service.AuthenticateLocalParams{
		RealmID: resetRealm, Identifier: "erin", Password: password, IPAddress: "198.51.100.9",
	})
	return err
}

func TestAuthenticateLocal_UpgradesAnOldHash(t *testing.T) {
	old := legacyHash(t, rehashPassword)
	users, auth := newRehashFixture(t, old)

	require.ErrorIs(t, signIn(auth, "wrong-password"), service.ErrInvalidCredentials)
	require.Equal(t, old, users.get("u-erin").PasswordHash, "a wrong password changes nothing")

	require.NoError(t, signIn(auth, rehashPassword))
	upgraded := users.get("u-erin").PasswordHash
	require.NotEqual(t, old, upgraded)
	require.True(t, strings.HasPrefix(upgraded, "$argon2id$v=19$m=65536,t=3,p=4$"), upgraded)

	// Same password, new hash: the next sign-ins work and change nothing.
	require.NoError(t, signIn(auth, rehashPassword))
	require.Equal(t, upgraded, users.get("u-erin").PasswordHash)
}

func TestAuthenticateLocal_CurrentHashIsLeftAlone(t *testing.T) {
	current, err := service.HashPassword(rehashPassword)
	require.NoError(t, err)
	users, auth := newRehashFixture(t, current)

	require.NoError(t, signIn(auth, rehashPassword))
	require.Equal(t, current, users.get("u-erin").PasswordHash)
}

// resetDuringSignIn changes the password (as a password reset would) just
// before the sign-in stores its re-hashed password.
type resetDuringSignIn struct {
	*memUsers
	resetHash string
}

func (r *resetDuringSignIn) CompareAndSwapPasswordHash(ctx context.Context, id, old, next string) (bool, error) {
	r.memUsers.mu.Lock()
	r.memUsers.byID[id].PasswordHash = r.resetHash
	r.memUsers.mu.Unlock()
	return r.memUsers.CompareAndSwapPasswordHash(ctx, id, old, next)
}

func TestAuthenticateLocal_UpgradeNeverUndoesAPasswordReset(t *testing.T) {
	users, _ := newRehashFixture(t, legacyHash(t, rehashPassword))
	racing := &resetDuringSignIn{memUsers: users, resetHash: "hash-of-the-new-password"}
	auth := service.NewAuthService(racing, &fakeLoginAttemptRepo{})

	require.NoError(t, signIn(auth, rehashPassword), "the old password was right when it was checked")
	require.Equal(t, "hash-of-the-new-password", users.get("u-erin").PasswordHash,
		"the reset wins: the old password must not come back")
}
