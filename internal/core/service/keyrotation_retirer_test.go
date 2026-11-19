package service_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/keymanager"
)

// lockedBuf is a log destination the test can read while RunRetirer writes.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// failingKM cannot create keys (the KMS is down) and counts the attempts.
type failingKM struct {
	keymanager.KeyManager
	calls atomic.Int32
}

func (k *failingKM) GenerateKey(context.Context, keymanager.KeyType, int) (*keymanager.GeneratedKey, error) {
	k.calls.Add(1)
	return nil, errors.New("kms down")
}

// runRetirer runs RunRetirer (one realm, a 5 ms tick) until `until` is true,
// then `extra` longer, and waits for it to stop.
func runRetirer(t *testing.T, rot *service.KeyRotationService, until func() bool, extra time.Duration) {
	t.Helper()
	realms := func(context.Context) ([]*domain.Realm, error) { return []*domain.Realm{{ID: rotRealm}}, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		rot.RunRetirer(ctx, realms, 5*time.Millisecond)
	}()
	require.Eventually(t, until, 5*time.Second, 5*time.Millisecond)
	time.Sleep(extra)
	cancel()
	<-done
}

func TestRunRetirer_RotatesWhatIsDue(t *testing.T) {
	f := newRotFixtureOn(t, "vault")
	f.settings.intervalDays = 90
	first := f.rotate(t, service.RotateInput{}).NewKey
	f.advance(91 * 24 * time.Hour)

	runRetirer(t, f.rot, func() bool {
		keys, err := f.rot.List(context.Background(), rotRealm)
		return err == nil && len(keys) == 2
	}, 50*time.Millisecond)

	keys, err := f.rot.List(context.Background(), rotRealm)
	require.NoError(t, err)
	require.Len(t, keys, 2, "rotated once, not at every tick")
	require.NotEqual(t, first.Kid, f.signerKid(t))
}

func TestRunRetirer_FailedRotationIsLoggedAndRetriedLater(t *testing.T) {
	f := newRotFixtureOn(t, "vault")
	f.settings.intervalDays = 90
	f.rotate(t, service.RotateInput{})
	f.advance(91 * 24 * time.Hour)

	km := &failingKM{KeyManager: f.km}
	logs := &lockedBuf{}
	rot := service.NewKeyRotationService(f.keys, f.logs, f.settings, km, "vault",
		service.WithKeyRotationClock(func() time.Time { return f.now }),
		service.WithKeyRotationLogger(slog.New(slog.NewTextHandler(logs, nil))))

	// Many ticks pass after the failure: the claim is still held, so no new try.
	runRetirer(t, rot, func() bool { return strings.Contains(logs.String(), "key auto-rotation failed") }, 50*time.Millisecond)

	require.Contains(t, logs.String(), "level=ERROR")
	require.Contains(t, logs.String(), "kms down")
	require.EqualValues(t, 1, km.calls.Load(), "one try, then the claim holds the others off")
	require.True(t, f.settings.claimedUntil.After(f.now), "the claim is kept after a failure")
}
