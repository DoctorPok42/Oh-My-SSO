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
	Device    string    `json:"dev,omitempty"`
	Methods   []string  `json:"m"`             // methods that may answer this challenge
	CreatedAt time.Time `json:"cat"`
	ExpiresAt time.Time `json:"exp"`
	// RememberMe: "Keep me signed in" was ticked with the password; the
	// session created after the second factor is a remembered one.
	RememberMe bool `json:"rm,omitempty"`
}

type Ceremony struct {
	Purpose     string          `json:"p"` // "register", "login", "step_up" or "passwordless"
	RealmID     string          `json:"rid"`
	UserID      string          `json:"uid"`
	SessionData json.RawMessage `json:"sd"`
	// Registration only: what the user asked to create.
	Kind string `json:"kind,omitempty"` // "passkey" or "security_key"
	Name string `json:"name,omitempty"`
	// Login / step-up: which factor types may answer.
	Methods   []string  `json:"m,omitempty"`
	ExpiresAt time.Time `json:"exp"`
	// Sign-in without password only ("passwordless"). UserID is then empty
	// when the authenticator itself tells who signs in (discoverable
	// passkey). ClientRef: the application the sign-in is for.
	ClientRef string `json:"cref,omitempty"`
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
