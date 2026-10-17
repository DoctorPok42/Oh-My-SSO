// Package passkeytest is a software WebAuthn authenticator for tests.
//
// It plays the part of the browser + authenticator pair (Face ID, a
// YubiKey...): it takes the options JSON a server sends to
// navigator.credentials.create() / .get() and returns the JSON the browser
// would send back, with real P-256 keys and real signatures. Tests can run
// the full ceremonies without a browser, and check that tampering is caught.
//
// Never use it outside tests.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

var b64 = base64.RawURLEncoding

// Authenticator holds credentials like a phone or a security key would.
type Authenticator struct {
	mu     sync.Mutex
	origin string
	creds  []*credential

	// UserVerification: the authenticator verifies the user (biometrics /
	// PIN) and sets the UV flag. Default true.
	UserVerification bool
	// BackupEligible: credentials can be synced (BE/BS flags), like an
	// iCloud Keychain passkey. Default true.
	BackupEligible bool
	// Discoverable: honour residentKey requests and report credProps.rk.
	// Default true. Set false to mimic an old security key.
	Discoverable bool
}

type credential struct {
	id           []byte
	rpID         string
	userHandle   []byte
	key          *ecdsa.PrivateKey
	signCount    uint32
	discoverable bool
	backup       bool
}

// New returns an authenticator answering as if loaded from origin
// (e.g. "https://sso.test"). The server must list that origin.
func New(origin string) *Authenticator {
	return &Authenticator{origin: origin, UserVerification: true, BackupEligible: true, Discoverable: true}
}

// Origin used in clientDataJSON (lets a test fake a phishing site).
func (a *Authenticator) SetOrigin(origin string) { a.origin = origin }

// Count returns how many credentials the authenticator holds.
func (a *Authenticator) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.creds)
}

// SetSignCount forces the counter of every credential (to simulate a cloned
// authenticator, whose counter goes backwards).
func (a *Authenticator) SetSignCount(n uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.creds {
		c.signCount = n
	}
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		Extensions map[string]any `json:"extensions"`
	} `json:"publicKey"`
}

// Create answers navigator.credentials.create({publicKey}).
func (a *Authenticator) Create(optionsJSON []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, fmt.Errorf("passkeytest: bad creation options: %w", err)
	}
	pk := o.PublicKey
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ex := range pk.ExcludeCredentials {
		for _, c := range a.creds {
			if b64.EncodeToString(c.id) == ex.ID {
				return nil, errors.New("passkeytest: InvalidStateError: this authenticator is already registered")
			}
		}
	}
	if pk.AuthenticatorSelection.UserVerification == "required" && !a.UserVerification {
		return nil, errors.New("passkeytest: NotAllowedError: user verification required but not available")
	}
	if pk.AuthenticatorSelection.ResidentKey == "required" && !a.Discoverable {
		return nil, errors.New("passkeytest: NotAllowedError: cannot create a discoverable credential")
	}
	userHandle, err := b64.DecodeString(pk.User.ID)
	if err != nil {
		return nil, fmt.Errorf("passkeytest: bad user.id: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	c := &credential{
		id: id, rpID: pk.RP.ID, userHandle: userHandle, key: key,
		discoverable: a.Discoverable && pk.AuthenticatorSelection.ResidentKey != "discouraged",
		backup:       a.BackupEligible,
	}
	a.creds = append(a.creds, c)

	clientData, _ := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": pk.Challenge, "origin": a.origin, "crossOrigin": false,
	})

	// Attested credential data: AAGUID (zeros: "none" attestation), length,
	// id, COSE public key.
	attested := make([]byte, 16, 128)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(id)))
	attested = append(attested, id...)
	attested = append(attested, coseEC2Key(&key.PublicKey)...)
	authData := a.authData(c, 0x40, attested) // 0x40 = AT: attested data present

	attObj := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(authData),
	)

	ext := map[string]any{}
	if _, ok := pk.Extensions["credProps"]; ok {
		ext["credProps"] = map[string]any{"rk": c.discoverable}
	}
	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(id),
		"rawId":                   b64.EncodeToString(id),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  ext,
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal", "hybrid"},
		},
	})
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// Get answers navigator.credentials.get({publicKey}) with the first stored
// credential allowed by the options.
func (a *Authenticator) Get(optionsJSON []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, fmt.Errorf("passkeytest: bad request options: %w", err)
	}
	pk := o.PublicKey
	a.mu.Lock()
	defer a.mu.Unlock()

	var c *credential
	for _, cand := range a.creds {
		if cand.rpID != pk.RPID {
			continue
		}
		if len(pk.AllowCredentials) == 0 && cand.discoverable {
			c = cand
			break
		}
		for _, allowed := range pk.AllowCredentials {
			if allowed.ID == b64.EncodeToString(cand.id) {
				c = cand
			}
		}
		if c != nil {
			break
		}
	}
	if c == nil {
		return nil, errors.New("passkeytest: NotAllowedError: no matching credential on this authenticator")
	}
	if pk.UserVerification == "required" && !a.UserVerification {
		return nil, errors.New("passkeytest: NotAllowedError: user verification required but not available")
	}

	c.signCount++
	clientData, _ := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": pk.Challenge, "origin": a.origin, "crossOrigin": false,
	})
	authData := a.authData(c, 0, nil)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(c.id),
		"rawId":                   b64.EncodeToString(c.id),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.userHandle),
		},
	})
}

// authData = SHA-256(rpId) | flags | signCount | [attested credential data]
// Flags: UP 0x01, UV 0x04, BE 0x08, BS 0x10, AT 0x40 (WebAuthn §6.1).
func (a *Authenticator) authData(c *credential, extraFlags byte, attested []byte) []byte {
	rpHash := sha256.Sum256([]byte(c.rpID))
	flags := byte(0x01) | extraFlags
	if a.UserVerification {
		flags |= 0x04
	}
	if c.backup {
		flags |= 0x08 | 0x10
	}
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, c.signCount)
	return append(out, attested...)
}

// --- just enough CBOR (RFC 8949) for COSE keys and attestation objects ---

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	}
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(kv ...[]byte) []byte {
	out := cborHead(5, uint64(len(kv)/2))
	for _, part := range kv {
		out = append(out, part...)
	}
	return out
}

// coseEC2Key encodes a P-256 public key as a COSE_Key (RFC 9053 §7.1.1):
// {1: 2 (kty EC2), 3: -7 (alg ES256), -1: 1 (crv P-256), -2: x, -3: y}.
func coseEC2Key(pub *ecdsa.PublicKey) []byte {
	raw, _ := pub.Bytes() // 0x04 || X (32) || Y (32)
	return cborMap(
		cborInt(1), cborInt(2),
		cborInt(3), cborInt(-7),
		cborInt(-1), cborInt(1),
		cborInt(-2), cborBytes(raw[1:33]),
		cborInt(-3), cborBytes(raw[33:65]),
	)
}
