// Package passkey is the WebAuthn engine of Oh-My-SSO (Step 9b), built on
// github.com/go-webauthn/webauthn. It implements service.PasskeyProvider.
//
// It lives outside internal/core because go-webauthn imports net/http, and
// the core must stay free of HTTP (make check-core-deps). The core only
// exchanges JSON (what the browser sends and receives) and opaque state
// with it.
//
// Library: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn
// Spec:    https://www.w3.org/TR/webauthn-3/
package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/service"
)

// Config of the relying party (RP) = this SSO server, as browsers see it.
type Config struct {
	// RPID is the domain passkeys are bound to, without scheme or port:
	// "sso.example.com", or "localhost" in development. A passkey created
	// for one RP ID never works for another (that is what stops phishing).
	// Changing it later makes every registered passkey unusable.
	RPID string
	// RPDisplayName is shown by the browser / OS ("Oh-My-SSO").
	RPDisplayName string
	// RPOrigins are the exact origins the login pages are served from,
	// e.g. "https://sso.example.com" or "http://localhost:8080".
	RPOrigins []string
}

// ceremonyTimeout is how long the browser waits for the user, and how long
// the server accepts the answer.
const ceremonyTimeout = 5 * time.Minute

// Provider implements service.PasskeyProvider.
type Provider struct {
	wa *webauthn.WebAuthn
}

var _ service.PasskeyProvider = (*Provider)(nil)

// New validates the configuration and builds the provider.
func New(cfg Config) (*Provider, error) {
	if cfg.RPID == "" || len(cfg.RPOrigins) == 0 {
		return nil, errors.New("passkey: RPID and at least one RP origin are required")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = "Oh-My-SSO"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		// "none": we do not ask which exact authenticator model is used.
		// Better for privacy, and we do not restrict models (no FIDO MDS).
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: %w", err)
	}
	return &Provider{wa: wa}, nil
}

// user adapts domain.User to the webauthn.User interface.
//
// The user handle (WebAuthnID) is User.ID: a random UUID, stable, opaque, and
// never personal data (WebAuthn §14.6.1 forbids putting an email there).
type user struct {
	u     *domain.User
	creds []webauthn.Credential
}

func (w *user) WebAuthnID() []byte   { return []byte(w.u.ID) }
func (w *user) WebAuthnName() string { return w.u.Username }
func (w *user) WebAuthnDisplayName() string {
	if w.u.Email != "" {
		return w.u.Email
	}
	return w.u.Username
}
func (w *user) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func newUser(u *domain.User, methods []*domain.MfaMethod) (*user, error) {
	w := &user{u: u}
	for _, m := range methods {
		if !m.IsWebAuthn() || m.WebAuthnCredential == "" {
			continue
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(m.WebAuthnCredential), &c); err != nil {
			return nil, fmt.Errorf("passkey: credential %s is corrupted: %w", m.ID, err)
		}
		w.creds = append(w.creds, c)
	}
	return w, nil
}

func descriptors(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		out = append(out, creds[i].Descriptor())
	}
	return out
}

// BeginRegistration builds PublicKeyCredentialCreationOptions.
func (p *Provider) BeginRegistration(u *domain.User, existing []*domain.MfaMethod, kind service.PasskeyKind) ([]byte, []byte, error) {
	wu, err := newUser(u, existing)
	if err != nil {
		return nil, nil, err
	}
	sel := protocol.AuthenticatorSelection{UserVerification: protocol.VerificationPreferred}
	switch kind {
	case service.PasskeyKindPasskey:
		// A passkey must be discoverable and unlocked by the user
		// (biometrics or device PIN): it can become a primary login later.
		sel.ResidentKey = protocol.ResidentKeyRequirementRequired
		sel.RequireResidentKey = protocol.ResidentKeyRequired()
		sel.UserVerification = protocol.VerificationRequired
	case service.PasskeyKindSecurityKey:
		sel.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
		sel.RequireResidentKey = protocol.ResidentKeyNotRequired()
	default:
		return nil, nil, service.ErrUnknownPasskeyKind
	}

	creation, session, err := p.wa.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithExclusions(descriptors(wu.creds)),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		// credProps tells us whether a discoverable credential was created.
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin registration: %w", err)
	}
	return marshalPair(creation, session)
}

// FinishRegistration verifies the RegistrationResponseJSON sent by the browser.
func (p *Provider) FinishRegistration(u *domain.User, existing []*domain.MfaMethod, kind service.PasskeyKind, state, response []byte) (*service.NewPasskey, error) {
	wu, err := newUser(u, existing)
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return nil, fmt.Errorf("passkey: bad session state: %w", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("passkey: parse registration: %w", describe(err))
	}
	cred, err := p.wa.CreateCredential(wu, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("passkey: verify registration: %w", describe(err))
	}

	// credProps.rk says what the authenticator really created. Without it,
	// trust the request: a "passkey" request requires a resident key, an
	// authenticator that cannot create one fails the ceremony instead.
	discoverable := kind == service.PasskeyKindPasskey
	if cred.Extensions.RK != nil {
		discoverable = *cred.Extensions.RK
	}

	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	return &service.NewPasskey{
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      base64.StdEncoding.EncodeToString(cred.PublicKey),
		Discoverable:   discoverable,
		BackupEligible: cred.Flags.BackupEligible,
		CredentialJSON: string(raw),
	}, nil
}

// BeginLogin builds PublicKeyCredentialRequestOptions limited to the given
// credentials (second factor: we already know who is logging in).
func (p *Provider) BeginLogin(u *domain.User, credentials []*domain.MfaMethod) ([]byte, []byte, error) {
	wu, err := newUser(u, credentials)
	if err != nil {
		return nil, nil, err
	}
	if len(wu.creds) == 0 {
		return nil, nil, errors.New("passkey: no credential to log in with")
	}
	assertion, session, err := p.wa.BeginLogin(wu,
		webauthn.WithAllowedCredentials(descriptors(wu.creds)),
		// Second factor: the password was the first one, presence is enough;
		// authenticators that can verify the user will still do it.
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: begin login: %w", err)
	}
	return marshalPair(assertion, session)
}

// FinishLogin verifies the AuthenticationResponseJSON sent by the browser.
func (p *Provider) FinishLogin(u *domain.User, credentials []*domain.MfaMethod, state, response []byte) (*service.PasskeyAssertion, error) {
	wu, err := newUser(u, credentials)
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return nil, fmt.Errorf("passkey: bad session state: %w", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("passkey: parse assertion: %w", describe(err))
	}
	cred, err := p.wa.ValidateLogin(wu, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("passkey: verify assertion: %w", describe(err))
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	return &service.PasskeyAssertion{
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		CredentialJSON: string(raw),
		CloneWarning:   cred.Authenticator.CloneWarning,
		UserVerified:   parsed.Response.AuthenticatorData.Flags.HasUserVerified(),
	}, nil
}

func marshalPair(options, session any) ([]byte, []byte, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	s, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return o, s, nil
}

// describe adds the library's developer detail ("Error validating origin"...)
// to the error, for the server logs only.
func describe(err error) error {
	var perr *protocol.Error
	if errors.As(err, &perr) && perr.DevInfo != "" {
		return fmt.Errorf("%w (%s)", err, perr.DevInfo)
	}
	return err
}
