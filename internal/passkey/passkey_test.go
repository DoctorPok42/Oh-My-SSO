package passkey_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
	"sso.internal/sso/internal/passkey"
	"sso.internal/sso/internal/passkey/passkeytest"
)

const origin = "https://sso.test"

func newProvider(t *testing.T) *passkey.Provider {
	t.Helper()
	p, err := passkey.New(passkey.Config{RPID: "sso.test", RPDisplayName: "Oh-My-SSO test", RPOrigins: []string{origin}})
	require.NoError(t, err)
	return p
}

var alice = &domain.User{ID: "4f0c3c8e-1d5b-4b7e-9f44-0a7d2b8e9c11", RealmID: "realm-1", Username: "alice", Email: "alice@example.test"}

// register runs a full registration ceremony and returns the stored method.
func register(t *testing.T, p *passkey.Provider, auth *passkeytest.Authenticator, existing []*domain.MfaMethod, kind service.PasskeyKind) (*service.NewPasskey, *domain.MfaMethod) {
	t.Helper()
	options, state, err := p.BeginRegistration(alice, existing, kind)
	require.NoError(t, err)
	response, err := auth.Create(options)
	require.NoError(t, err)
	np, err := p.FinishRegistration(alice, existing, kind, state, response)
	require.NoError(t, err)
	typ := domain.MfaMethodWebAuthn
	if np.Discoverable {
		typ = domain.MfaMethodPasskey
	}
	return np, &domain.MfaMethod{ID: "m-" + np.CredentialID[:6], UserID: alice.ID, Type: typ, Status: domain.MfaMethodActive,
		CredentialID: np.CredentialID, IsDiscoverable: np.Discoverable, WebAuthnCredential: np.CredentialJSON}
}

func TestNew(t *testing.T) {
	_, err := passkey.New(passkey.Config{})
	require.Error(t, err, "RPID and origins are mandatory")
}

func TestRegistrationAndLogin(t *testing.T) {
	p := newProvider(t)
	auth := passkeytest.New(origin)

	options, _, err := p.BeginRegistration(alice, nil, service.PasskeyKindPasskey)
	require.NoError(t, err)
	var o map[string]any
	require.NoError(t, json.Unmarshal(options, &o))
	pk := o["publicKey"].(map[string]any)
	require.Equal(t, "sso.test", pk["rp"].(map[string]any)["id"])
	require.Equal(t, "none", pk["attestation"], "no attestation: better privacy")
	sel := pk["authenticatorSelection"].(map[string]any)
	require.Equal(t, "required", sel["residentKey"])
	require.Equal(t, "required", sel["userVerification"])
	handle, err := base64.RawURLEncoding.DecodeString(pk["user"].(map[string]any)["id"].(string))
	require.NoError(t, err)
	require.Equal(t, alice.ID, string(handle), "the user handle is the opaque user id, never the email")

	np, m := register(t, p, auth, nil, service.PasskeyKindPasskey)
	require.True(t, np.Discoverable)
	require.True(t, np.BackupEligible, "synced passkey")
	require.NotEmpty(t, np.PublicKey)

	// Second factor login.
	options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
	require.NoError(t, err)
	require.Contains(t, string(options), np.CredentialID, "only the user's credentials may answer")
	response, err := auth.Get(options)
	require.NoError(t, err)
	a, err := p.FinishLogin(alice, []*domain.MfaMethod{m}, state, response)
	require.NoError(t, err)
	require.Equal(t, np.CredentialID, a.CredentialID)
	require.False(t, a.CloneWarning)
	require.True(t, a.UserVerified)
	require.Contains(t, a.CredentialJSON, `"signCount":1`, "updated counter to store")

	// The same signed answer cannot be replayed on a new challenge.
	_, state2, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
	require.NoError(t, err)
	_, err = p.FinishLogin(alice, []*domain.MfaMethod{m}, state2, response)
	require.Error(t, err, "challenge mismatch")
}

func TestSecurityKey(t *testing.T) {
	p := newProvider(t)
	auth := passkeytest.New(origin)
	auth.Discoverable = false
	auth.BackupEligible = false
	auth.UserVerification = false

	options, _, err := p.BeginRegistration(alice, nil, service.PasskeyKindSecurityKey)
	require.NoError(t, err)
	require.Contains(t, string(options), `"residentKey":"discouraged"`)

	np, m := register(t, p, auth, nil, service.PasskeyKindSecurityKey)
	require.False(t, np.Discoverable)
	require.Equal(t, domain.MfaMethodWebAuthn, m.Type)

	// No user verification is fine for a second factor (presence only).
	options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
	require.NoError(t, err)
	response, err := auth.Get(options)
	require.NoError(t, err)
	a, err := p.FinishLogin(alice, []*domain.MfaMethod{m}, state, response)
	require.NoError(t, err)
	require.False(t, a.UserVerified)

	// A passkey request needs user verification: this key cannot do it.
	options, _, err = p.BeginRegistration(alice, []*domain.MfaMethod{m}, service.PasskeyKindPasskey)
	require.NoError(t, err)
	_, err = auth.Create(options)
	require.Error(t, err)
}

func TestAttacks(t *testing.T) {
	p := newProvider(t)

	t.Run("phishing site: wrong origin is refused", func(t *testing.T) {
		auth := passkeytest.New("https://sso-test.evil.example")
		options, state, err := p.BeginRegistration(alice, nil, service.PasskeyKindPasskey)
		require.NoError(t, err)
		response, err := auth.Create(options)
		require.NoError(t, err)
		_, err = p.FinishRegistration(alice, nil, service.PasskeyKindPasskey, state, response)
		require.Error(t, err)
	})

	t.Run("already registered authenticator is excluded", func(t *testing.T) {
		auth := passkeytest.New(origin)
		_, m := register(t, p, auth, nil, service.PasskeyKindPasskey)
		options, _, err := p.BeginRegistration(alice, []*domain.MfaMethod{m}, service.PasskeyKindPasskey)
		require.NoError(t, err)
		require.Contains(t, string(options), m.CredentialID, "excludeCredentials lists it")
		_, err = auth.Create(options)
		require.ErrorContains(t, err, "InvalidStateError")
	})

	t.Run("cloned authenticator: counter going backwards is flagged", func(t *testing.T) {
		auth := passkeytest.New(origin)
		_, m := register(t, p, auth, nil, service.PasskeyKindPasskey)
		for i := 0; i < 2; i++ {
			options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
			require.NoError(t, err)
			response, err := auth.Get(options)
			require.NoError(t, err)
			a, err := p.FinishLogin(alice, []*domain.MfaMethod{m}, state, response)
			require.NoError(t, err)
			m.WebAuthnCredential = a.CredentialJSON // stored counter = 1, then 2
		}
		auth.SetSignCount(0) // next answer carries counter 1 < 2
		options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
		require.NoError(t, err)
		response, err := auth.Get(options)
		require.NoError(t, err)
		a, err := p.FinishLogin(alice, []*domain.MfaMethod{m}, state, response)
		require.NoError(t, err)
		require.True(t, a.CloneWarning)
	})

	t.Run("someone else's credential cannot answer", func(t *testing.T) {
		auth := passkeytest.New(origin)
		_, mine := register(t, p, auth, nil, service.PasskeyKindPasskey)
		other := passkeytest.New(origin)
		_, theirs := register(t, p, other, nil, service.PasskeyKindPasskey)

		options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{mine})
		require.NoError(t, err)
		// The other authenticator only holds a credential that was not allowed.
		_, err = other.Get(options)
		require.Error(t, err)
		_ = theirs
		_ = state
	})

	t.Run("tampered response", func(t *testing.T) {
		auth := passkeytest.New(origin)
		_, m := register(t, p, auth, nil, service.PasskeyKindPasskey)
		options, state, err := p.BeginLogin(alice, []*domain.MfaMethod{m})
		require.NoError(t, err)
		response, err := auth.Get(options)
		require.NoError(t, err)
		var r map[string]any
		require.NoError(t, json.Unmarshal(response, &r))
		resp := r["response"].(map[string]any)
		sig := resp["signature"].(string)
		resp["signature"] = strings.Repeat("A", len(sig))
		tampered, _ := json.Marshal(r)
		_, err = p.FinishLogin(alice, []*domain.MfaMethod{m}, state, tampered)
		require.Error(t, err)
	})
}
