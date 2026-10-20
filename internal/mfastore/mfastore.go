// Package mfastore holds the short-lived state of MFA ceremonies: the login
// challenge between "password OK" and "second factor OK" (Step 9a), and
// later the WebAuthn challenges (Step 9b).
//
// Everything here expires within minutes and can be lost without harm (the
// user just starts again), which is why it lives in Valkey rather than in
// Postgres. Keys are always hashes of the random token sent to the browser,
// never the token itself, so a dump of Valkey cannot be replayed.
package mfastore

import (
	"context"
	"encoding/json"
	"time"
)

// LoginChallenge is created when the password was correct but a second
// factor is still needed. No session exists yet.
type LoginChallenge struct {
	RealmID   string    `json:"rid"`
	UserID    string    `json:"uid"`
	ClientRef string    `json:"cref,omitempty"` // ClientApp.ID the login is for, if any
	IPAddress string    `json:"ip,omitempty"`
	UserAgent string    `json:"ua,omitempty"`
	Device    string    `json:"dev,omitempty"` // Step 12: device fingerprint (hash) for the session
	Methods   []string  `json:"m"`             // methods that may answer this challenge
	CreatedAt time.Time `json:"cat"`
	ExpiresAt time.Time `json:"exp"`
}

// Ceremony is a WebAuthn ceremony in progress (Step 9b): the server sent
// options with a random challenge to the browser and waits for the signed
// answer. SessionData is go-webauthn's state, stored verbatim (the library
// asks for that: a hand-rebuilt copy loses information).
type Ceremony struct {
	Purpose     string          `json:"p"` // "register", "login" or "step_up"
	RealmID     string          `json:"rid"`
	UserID      string          `json:"uid"`
	SessionData json.RawMessage `json:"sd"`
	// Registration only: what the user asked to create.
	Kind string `json:"kind,omitempty"` // "passkey" or "security_key"
	Name string `json:"name,omitempty"`
	// Login / step-up: which factor types may answer.
	Methods   []string  `json:"m,omitempty"`
	ExpiresAt time.Time `json:"exp"`
}

// Store is implemented by Valkey (production) and Memory (tests).
type Store interface {
	SaveChallenge(ctx context.Context, key string, c LoginChallenge, ttl time.Duration) error
	// GetChallenge returns (nil, nil) when the challenge does not exist or
	// expired.
	GetChallenge(ctx context.Context, key string) (*LoginChallenge, error)
	// IncrementAttempts counts one more answer to the challenge and returns
	// the new count (1 for the first attempt).
	IncrementAttempts(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// TakeChallenge deletes the challenge and tells whether this call is the
	// one that deleted it. A challenge can be used exactly once, even when
	// two requests race.
	TakeChallenge(ctx context.Context, key string) (bool, error)

	SaveCeremony(ctx context.Context, key string, c Ceremony, ttl time.Duration) error
	// TakeCeremony returns and deletes the ceremony in one atomic step:
	// a WebAuthn challenge can be answered once. (nil, nil) if absent.
	TakeCeremony(ctx context.Context, key string) (*Ceremony, error)
}
