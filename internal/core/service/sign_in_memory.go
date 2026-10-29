package service

import (
	"context"
	"errors"
	"slices"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// Step 18e: a device remembers how its account likes to sign in.
//
//   - The tile starts with the method the user last chose there: the
//     password, or the passkey (the default).
//   - The second step (and "Confirm it's you") starts with the second
//     factor the user last chose there: a passkey or security key (the
//     default), or the authenticator app.
//
// Only on a device that remembers the account (a known account, "Keep me
// signed in"), and only a real choice: something else was offered. It
// changes the order of the methods, never which ones are accepted. Backup
// codes are never remembered: they stay a last resort.

// The kinds of second factor the page shows (a passkey and a security key
// are one choice there).
const (
	secondFactorPasskey = "passkey"
	secondFactorTOTP    = "totp"
)

// SignInMemory is what MFAService needs from KnownAccountService: read and
// record the second factor a user prefers on a device (deviceHash:
// DeviceFingerprint of the sso_device cookie).
type SignInMemory interface {
	// PreferredSecondFactor returns "passkey", "totp", or "" (none: the
	// best one first).
	PreferredSecondFactor(ctx context.Context, realmID, deviceHash, userID string) string
	// SecondFactorUsed is told which factor answered a sign-in challenge
	// that offered the methods in offered.
	SecondFactorUsed(ctx context.Context, realmID, deviceHash, userID string, used domain.MfaMethodType, offered []domain.MfaMethodType)
}

var _ SignInMemory = (*KnownAccountService)(nil)

// PasswordChosenInput: a correct password typed on a tile.
type PasswordChosenInput struct {
	RealmID   string
	DeviceID  string // raw sso_device cookie of the browser
	AccountID string // the tile (known account) the password was typed on
	UserID    string // whose password it is
	// Offered: the methods the tile offered for this application
	// (MFAService.SignInMethods).
	Offered []core.SignInMethod
}

// PasswordChosen: the user typed their password on a tile that also offered
// a passkey. Next time, the tile starts with the password. Anything else
// (no passkey offered, a tile of another device or of another account)
// changes nothing. Best effort: a failure is logged.
func (s *KnownAccountService) PasswordChosen(ctx context.Context, in PasswordChosenInput) {
	if in.AccountID == "" || !slices.Contains(in.Offered, core.SignInPasskey) {
		return
	}
	row, err := s.owned(ctx, in.RealmID, in.DeviceID, in.AccountID)
	if err != nil {
		if !errors.Is(err, ErrKnownAccountNotFound) {
			s.logger.WarnContext(ctx, "known accounts: password chosen", "account_id", in.AccountID, "error", err)
		}
		return
	}
	if row.UserID != in.UserID {
		return // the tile of someone else: the user typed another identifier
	}
	m := string(core.SignInPassword)
	s.setLast(ctx, row.RealmID, row.DeviceHash, row.UserID, repository.LastMethodsParams{LastMethod: &m})
}

// PasskeySignIn: the user signed in without password on this device. The
// tile starts with the passkey again.
func (s *KnownAccountService) PasskeySignIn(ctx context.Context, realmID, deviceHash, userID string) {
	if deviceHash == "" {
		return
	}
	m := string(core.SignInPasskey)
	s.setLast(ctx, realmID, deviceHash, userID, repository.LastMethodsParams{LastMethod: &m})
}

// SecondFactorUsed (SignInMemory) remembers the second factor that answered
// a challenge offering both kinds (a passkey or security key, and an
// authenticator app). A backup code is never remembered.
func (s *KnownAccountService) SecondFactorUsed(ctx context.Context, realmID, deviceHash, userID string, used domain.MfaMethodType, offered []domain.MfaMethodType) {
	kind := secondFactorKind(used)
	if kind == "" || deviceHash == "" || len(secondFactorKinds(offered)) < 2 {
		return
	}
	s.setLast(ctx, realmID, deviceHash, userID, repository.LastMethodsParams{LastSecondFactor: &kind})
}

// PreferredSecondFactor (SignInMemory). A failure reads as "no preference".
func (s *KnownAccountService) PreferredSecondFactor(ctx context.Context, realmID, deviceHash, userID string) string {
	if deviceHash == "" {
		return ""
	}
	row, err := s.accounts.Find(ctx, realmID, deviceHash, userID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			s.logger.WarnContext(ctx, "known accounts: preferred second factor", "user_id", userID, "error", err)
		}
		return ""
	}
	return row.LastSecondFactor
}

func (s *KnownAccountService) setLast(ctx context.Context, realmID, deviceHash, userID string, p repository.LastMethodsParams) {
	if _, err := s.accounts.SetLastMethods(ctx, realmID, deviceHash, userID, p); err != nil {
		s.logger.WarnContext(ctx, "known accounts: remember the sign-in method", "user_id", userID, "error", err)
	}
}

// secondFactorKind: "passkey", "totp", or "" (backup codes, anything else).
func secondFactorKind(t domain.MfaMethodType) string {
	switch t {
	case domain.MfaMethodPasskey, domain.MfaMethodWebAuthn:
		return secondFactorPasskey
	case domain.MfaMethodTOTP:
		return secondFactorTOTP
	}
	return ""
}

// secondFactorKinds: the distinct kinds among methods.
func secondFactorKinds(methods []domain.MfaMethodType) []string {
	var out []string
	for _, m := range methods {
		if k := secondFactorKind(m); k != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// preferSecondFactor puts the methods of kind first, in their order, then
// the others. kind "" or not offered: methods unchanged.
func preferSecondFactor(methods []domain.MfaMethodType, kind string) []domain.MfaMethodType {
	if kind == "" {
		return methods
	}
	var first, rest []domain.MfaMethodType
	for _, m := range methods {
		if secondFactorKind(m) == kind {
			first = append(first, m)
		} else {
			rest = append(rest, m)
		}
	}
	if len(first) == 0 {
		return methods
	}
	return append(first, rest...)
}

// preferFirstStep puts last first when the tile offers it.
func preferFirstStep(methods []core.SignInMethod, last string) []core.SignInMethod {
	i := slices.Index(methods, core.SignInMethod(last))
	if i <= 0 {
		return methods
	}
	out := make([]core.SignInMethod, 0, len(methods))
	out = append(out, methods[i])
	out = append(out, methods[:i]...)
	return append(out, methods[i+1:]...)
}

// methodTypes turns stored method names back into types.
func methodTypes(names []string) []domain.MfaMethodType {
	out := make([]domain.MfaMethodType, 0, len(names))
	for _, n := range names {
		out = append(out, domain.MfaMethodType(n))
	}
	return out
}
