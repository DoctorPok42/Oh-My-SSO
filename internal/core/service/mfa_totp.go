package service

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// TOTP (RFC 6238): https://www.rfc-editor.org/rfc/rfc6238
//
// Parameters are the only ones every authenticator app understands:
// SHA-1, 6 digits, 30-second period, 160-bit secret (RFC 4226 §4 R6).
// SHA-1 is fine here: TOTP uses HMAC-SHA1, whose security does not rely on
// SHA-1 collision resistance.
const (
	totpPeriod     = 30
	totpDigits     = otp.DigitsSix
	totpAlgorithm  = otp.AlgorithmSHA1
	totpSecretSize = 20 // bytes = 160 bits

	// totpSkewSteps: accept the previous and the next 30 s window too, for
	// phones whose clock drifts a little (RFC 6238 §5.2 recommends at most
	// one step).
	totpSkewSteps = 1

	// A pending enrollment (QR code shown, never confirmed) expires.
	totpEnrollmentTTL = 10 * time.Minute
	totpQRSize        = 240
)

var (
	ErrInvalidMFACode       = errors.New("service: invalid mfa code")
	ErrMFAEnrollmentExpired = errors.New("service: mfa enrollment expired, start again")
	ErrMFAMethodNotFound    = errors.New("service: mfa method not found")
)

// TOTPEnrollment is shown to the user once: QR code + manual-entry secret.
type TOTPEnrollment struct {
	MethodID  string
	Secret    string // base32, for typing the key by hand
	URI       string // otpauth://totp/... (what the QR code contains)
	QRCodePNG string // data:image/png;base64,...
	ExpiresAt time.Time
}

// totpAAD binds an encrypted secret to its owner: copying the column onto
// another user's row produces something that does not decrypt.
func totpAAD(userID string) []byte {
	return []byte("oh-my-sso/mfa/totp-secret/v1|user:" + userID)
}

// StartTOTPEnrollment creates a pending TOTP for the user and returns what
// to display. Any previous unfinished TOTP enrollment of the user is dropped.
// An already active TOTP keeps working until the new one is confirmed.
func (s *MFAService) StartTOTPEnrollment(ctx context.Context, user *domain.User, name string) (*TOTPEnrollment, error) {
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 100 {
		return nil, fmt.Errorf("%w: name too long (100 characters max)", ErrInvalidMFAPolicy)
	}
	if _, err := s.methods.DeletePendingByUser(ctx, user.ID, domain.MfaMethodTOTP); err != nil {
		return nil, fmt.Errorf("start totp enrollment: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer(ctx, user.RealmID),
		AccountName: user.Username,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("start totp enrollment: generate secret: %w", err)
	}

	sealed, err := s.envelope.Seal(ctx, user.RealmID, []byte(key.Secret()), totpAAD(user.ID))
	if err != nil {
		return nil, fmt.Errorf("start totp enrollment: %w", err)
	}

	m, err := s.methods.Create(ctx, repository.CreateMfaMethodParams{
		UserID:          user.ID,
		Type:            domain.MfaMethodTOTP,
		Name:            name,
		Status:          domain.MfaMethodPending,
		SecretEncrypted: sealed,
	})
	if err != nil {
		return nil, fmt.Errorf("start totp enrollment: %w", err)
	}

	qr, err := qrDataURI(key)
	if err != nil {
		return nil, fmt.Errorf("start totp enrollment: %w", err)
	}
	created := m.CreatedAt
	if created.IsZero() {
		created = s.now()
	}
	return &TOTPEnrollment{
		MethodID:  m.ID,
		Secret:    key.Secret(),
		URI:       key.URL(),
		QRCodePNG: qr,
		ExpiresAt: created.Add(totpEnrollmentTTL),
	}, nil
}

// EnrollmentResult is returned when a new factor becomes active.
type EnrollmentResult struct {
	Method *domain.MfaMethod
	// BackupCodes are shown ONCE, only when this is the user's first factor.
	BackupCodes []string
	// Session is the caller's session, now MFA-verified (a correct code from
	// the new factor is a fresh second-factor verification).
	Session *domain.Session
}

// ConfirmTOTPEnrollment activates a pending TOTP with a first valid code.
func (s *MFAService) ConfirmTOTPEnrollment(ctx context.Context, user *domain.User, sess *domain.Session, methodID, code string) (*EnrollmentResult, error) {
	m, err := s.methods.GetByID(ctx, methodID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFAMethodNotFound
		}
		return nil, fmt.Errorf("confirm totp enrollment: %w", err)
	}
	// Never reveal that the id exists for another user.
	if m.UserID != user.ID || m.Type != domain.MfaMethodTOTP || m.Status != domain.MfaMethodPending {
		return nil, ErrMFAMethodNotFound
	}
	if s.now().After(m.CreatedAt.Add(totpEnrollmentTTL)) {
		_ = s.methods.Delete(ctx, m.ID)
		return nil, ErrMFAEnrollmentExpired
	}
	if err := s.allowAttempt(ctx, user); err != nil {
		return nil, err
	}

	secret, err := s.envelope.Open(ctx, m.SecretEncrypted, totpAAD(user.ID))
	if err != nil {
		return nil, fmt.Errorf("confirm totp enrollment: %w", err)
	}
	counter, ok := matchTOTP(string(secret), code, s.now())
	if !ok {
		return nil, ErrInvalidMFACode
	}

	before, err := s.activeFactors(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	hadTOTP := hasType(before, domain.MfaMethodTOTP) // new phone replacing the old one
	firstFactor := len(before) == 0

	activated, err := s.methods.ActivateTOTP(ctx, m.ID, counter, s.now())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMFAMethodNotFound
		}
		return nil, fmt.Errorf("confirm totp enrollment: %w", err)
	}

	res := &EnrollmentResult{Method: activated, Session: sess}
	if firstFactor {
		codes, err := s.replaceBackupCodes(ctx, user)
		if err != nil {
			return nil, err
		}
		res.BackupCodes = codes
	}

	if sess != nil {
		upd, err := s.sessions.MarkMFAVerified(ctx, sess, string(domain.MfaMethodTOTP))
		if err != nil {
			return nil, err
		}
		res.Session = upd
	}

	s.auditEvent(ctx, user, "mfa_method_enrolled", "MfaMethod", activated.ID, domain.AuditLogInfo, map[string]interface{}{
		"type":     string(activated.Type),
		"replaced": hadTOTP,
	})
	s.notify(ctx, user, domain.NotificationMfaMethodAdded, activated)
	return res, nil
}

// verifyTOTP checks a code against the user's active TOTP and consumes it.
func (s *MFAService) verifyTOTP(ctx context.Context, user *domain.User, code string) (bool, error) {
	factors, err := s.activeFactors(ctx, user.ID)
	if err != nil {
		return false, err
	}
	var m *domain.MfaMethod
	for _, f := range factors {
		if f.Type == domain.MfaMethodTOTP {
			m = f
			break
		}
	}
	if m == nil {
		return false, nil
	}

	secret, err := s.envelope.Open(ctx, m.SecretEncrypted, totpAAD(user.ID))
	if err != nil {
		return false, fmt.Errorf("verify totp: %w", err)
	}
	counter, ok := matchTOTP(string(secret), code, s.now())
	if !ok || counter <= m.LastUsedCounter {
		return false, nil // wrong, expired, or already used (replay)
	}
	consumed, err := s.methods.ConsumeTOTPCounter(ctx, m.ID, counter, s.now())
	if err != nil {
		return false, fmt.Errorf("verify totp: %w", err)
	}
	return consumed, nil
}

// matchTOTP returns the time step (counter) whose code equals the input,
// trying the current step first, then the previous and next ones.
func matchTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != int(totpDigits) || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	opts := hotp.ValidateOpts{Digits: totpDigits, Algorithm: totpAlgorithm}
	current := now.Unix() / totpPeriod
	for _, delta := range []int64{0, -1, 1}[:1+2*totpSkewSteps] {
		counter := current + delta
		if counter <= 0 {
			continue
		}
		want, err := hotp.GenerateCodeCustom(secret, uint64(counter), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

func qrDataURI(key *otp.Key) (string, error) {
	img, err := key.Image(totpQRSize, totpQRSize)
	if err != nil {
		return "", fmt.Errorf("qr code: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("qr code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func hasType(methods []*domain.MfaMethod, t domain.MfaMethodType) bool {
	for _, m := range methods {
		if m.Type == t {
			return true
		}
	}
	return false
}
