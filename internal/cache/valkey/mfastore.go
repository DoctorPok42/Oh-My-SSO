package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	"sso.internal/sso/internal/mfastore"
)

type mfaStore struct {
	client valkey.Client
}

// NewMFAStore returns the Valkey implementation of mfastore.Store.
func NewMFAStore(client valkey.Client) mfastore.Store {
	return &mfaStore{client: client}
}

// Same hash tag ({...}) for both keys of a challenge: they land on the same
// slot if Valkey ever runs as a cluster.
func challengeKey(key string) string { return "mfa:chal:{" + key + "}" }
func attemptsKey(key string) string  { return "mfa:chal:{" + key + "}:n" }
func ceremonyKey(key string) string  { return "mfa:webauthn:{" + key + "}" }

func (s *mfaStore) SaveChallenge(ctx context.Context, key string, c mfastore.LoginChallenge, ttl time.Duration) error {
	if ttl < minTTL {
		ttl = minTTL
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := s.client.Do(ctx, s.client.B().Set().
		Key(challengeKey(key)).Value(string(data)).
		Ex(ttl).
		Build()).Error(); err != nil {
		return fmt.Errorf("mfastore: save challenge: %w", err)
	}
	return nil
}

func (s *mfaStore) GetChallenge(ctx context.Context, key string) (*mfastore.LoginChallenge, error) {
	raw, err := s.client.Do(ctx, s.client.B().Get().Key(challengeKey(key)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mfastore: get challenge: %w", err)
	}
	var c mfastore.LoginChallenge
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("mfastore: decode challenge: %w", err)
	}
	return &c, nil
}

func (s *mfaStore) IncrementAttempts(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl < minTTL {
		ttl = minTTL
	}
	k := attemptsKey(key)
	n, err := s.client.Do(ctx, s.client.B().Incr().Key(k).Build()).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("mfastore: count attempt: %w", err)
	}
	if n == 1 {
		// First attempt: give the counter the same lifetime as the
		// challenge, so it never outlives it.
		if err := s.client.Do(ctx, s.client.B().Expire().Key(k).Seconds(int64(ttl/time.Second)).Build()).Error(); err != nil {
			return 0, fmt.Errorf("mfastore: expire attempt counter: %w", err)
		}
	}
	return n, nil
}

func (s *mfaStore) TakeChallenge(ctx context.Context, key string) (bool, error) {
	// DEL returns how many keys it removed: only one caller can get 1 for
	// the challenge key, which makes the challenge single-use.
	n, err := s.client.Do(ctx, s.client.B().Del().Key(challengeKey(key)).Build()).AsInt64()
	if err != nil {
		return false, fmt.Errorf("mfastore: take challenge: %w", err)
	}
	_ = s.client.Do(ctx, s.client.B().Del().Key(attemptsKey(key)).Build()).Error()
	return n == 1, nil
}

func (s *mfaStore) SaveCeremony(ctx context.Context, key string, c mfastore.Ceremony, ttl time.Duration) error {
	if ttl < minTTL {
		ttl = minTTL
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := s.client.Do(ctx, s.client.B().Set().
		Key(ceremonyKey(key)).Value(string(data)).
		Ex(ttl).
		Build()).Error(); err != nil {
		return fmt.Errorf("mfastore: save webauthn ceremony: %w", err)
	}
	return nil
}

func (s *mfaStore) TakeCeremony(ctx context.Context, key string) (*mfastore.Ceremony, error) {
	// GETDEL (Valkey / Redis >= 6.2): read and delete in one atomic command.
	raw, err := s.client.Do(ctx, s.client.B().Getdel().Key(ceremonyKey(key)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mfastore: take webauthn ceremony: %w", err)
	}
	var c mfastore.Ceremony
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Errorf("mfastore: decode webauthn ceremony: %w", err)
	}
	return &c, nil
}
