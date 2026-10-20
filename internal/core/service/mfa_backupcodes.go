package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"sso.internal/sso/internal/core/domain"
)

// Backup codes (recovery codes).
//
// 10 single-use codes like "K7Q2M-9XHRT", shown once. Only their Argon2id
// hash is stored, exactly like a password.
//
//   - Alphabet: Crockford base32 (no I, L, O, U), 32 symbols -> 5 bits each,
//     10 symbols = 50 bits of entropy per code.
//   - Input is forgiving: lower case, spaces and dashes are ignored, and the
//     look-alikes O/I/L are read as 0/1/1.
//   - One salt per batch: checking a code costs ONE Argon2id computation
//     (compared against the 10 stored hashes in constant time), instead of
//     ten. The 10 codes of a batch sharing a salt only makes an offline
//     attack on a stolen database 10x easier on 2^50 * Argon2id: still out
//     of reach.
//
// OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
const (
	backupCodeCount    = 10
	backupCodeLength   = 10
	backupCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// "Allégé" Argon2id: the OWASP minimum for passwords (m=19 MiB, t=2,
	// p=1). Much cheaper than our password hash (192 MiB, t=3), which is
	// fine for a 50-bit random code.
	backupCodeMemory      = 19 * 1024
	backupCodeIterations  = 2
	backupCodeParallelism = 1
	backupCodeKeyLength   = 32
	backupCodeSaltLength  = 16
)

var ErrNoMFAFactor = errors.New("service: enroll a second factor first")

// BackupCodesSummary is what the account console shows (never the codes).
type BackupCodesSummary struct {
	Remaining int
	Total     int
	BatchID   string
}

// generateBackupCodes returns 10 distinct codes formatted "XXXXX-XXXXX".
func generateBackupCodes() ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, backupCodeCount)
	for len(out) < backupCodeCount {
		raw := make([]byte, backupCodeLength)
		for i := range raw {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(backupCodeAlphabet))))
			if err != nil {
				return nil, err
			}
			raw[i] = backupCodeAlphabet[n.Int64()]
		}
		code := string(raw)
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code[:5]+"-"+code[5:])
	}
	return out, nil
}

// normalizeBackupCode turns what the user typed into the canonical form
// (10 upper-case symbols, no separator). ok is false for anything that
// cannot be a backup code.
func normalizeBackupCode(input string) (string, bool) {
	r := strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1")
	code := r.Replace(strings.ToUpper(strings.TrimSpace(input)))
	if len(code) != backupCodeLength {
		return "", false
	}
	for _, c := range code {
		if !strings.ContainsRune(backupCodeAlphabet, c) {
			return "", false
		}
	}
	return code, true
}

// hashBackupCodes hashes a batch with one shared random salt.
func hashBackupCodes(codes []string) ([]string, error) {
	salt := make([]byte, backupCodeSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		norm, ok := normalizeBackupCode(c)
		if !ok {
			return nil, fmt.Errorf("backup code %q is not valid", c)
		}
		key := argon2.IDKey([]byte(norm), salt, backupCodeIterations, backupCodeMemory, backupCodeParallelism, backupCodeKeyLength)
		out = append(out, encodeArgon2id(backupCodeMemory, backupCodeIterations, backupCodeParallelism, salt, key))
	}
	return out, nil
}

// replaceBackupCodes creates a new batch for the user (the old one stops
// working in the same transaction) and returns the clear codes, to be shown
// once.
func (s *MFAService) replaceBackupCodes(ctx context.Context, user *domain.User) ([]string, error) {
	codes, err := generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("backup codes: %w", err)
	}
	hashes, err := hashBackupCodes(codes)
	if err != nil {
		return nil, fmt.Errorf("backup codes: %w", err)
	}
	if err := s.codes.ReplaceForUser(ctx, user.ID, uuid.NewString(), hashes); err != nil {
		return nil, fmt.Errorf("backup codes: %w", err)
	}
	return codes, nil
}

// RegenerateBackupCodes invalidates the user's batch and returns a new one.
// Backup codes are a fallback for another factor: a user without any other
// active factor cannot have them.
func (s *MFAService) RegenerateBackupCodes(ctx context.Context, user *domain.User) ([]string, error) {
	factors, err := s.activeFactors(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(factors) == 0 {
		return nil, ErrNoMFAFactor
	}
	codes, err := s.replaceBackupCodes(ctx, user)
	if err != nil {
		return nil, err
	}
	s.auditEvent(ctx, user, "mfa_backup_codes_regenerated", "MfaBackupCode", user.ID, domain.AuditLogWarning, nil)
	s.notify(ctx, user, domain.NotificationBackupCodesRegenerated, nil)
	return codes, nil
}

// backupCodesSummary counts the remaining codes.
func (s *MFAService) backupCodesSummary(ctx context.Context, userID string) (BackupCodesSummary, error) {
	all, err := s.codes.ListByUser(ctx, userID)
	if err != nil {
		return BackupCodesSummary{}, fmt.Errorf("backup codes: %w", err)
	}
	var sum BackupCodesSummary
	for _, c := range all {
		sum.Total++
		sum.BatchID = c.BatchID
		if !c.Used {
			sum.Remaining++
		}
	}
	return sum, nil
}

// dummyBackupSalt keeps the cost of a failed check the same when the user
// has no code at all (no timing hint about it).
var dummyBackupSalt = []byte("oh-my-sso-dummy!")

// verifyBackupCode checks the input against the user's unused codes and
// consumes the matching one.
func (s *MFAService) verifyBackupCode(ctx context.Context, user *domain.User, input string) (bool, error) {
	norm, ok := normalizeBackupCode(input)
	if !ok {
		return false, nil
	}
	codes, err := s.codes.ListUnusedByUser(ctx, user.ID)
	if err != nil {
		return false, fmt.Errorf("verify backup code: %w", err)
	}
	if len(codes) == 0 {
		_ = argon2.IDKey([]byte(norm), dummyBackupSalt, backupCodeIterations, backupCodeMemory, backupCodeParallelism, backupCodeKeyLength)
		return false, nil
	}

	// One Argon2id computation per distinct (parameters, salt): normally one
	// per batch.
	computed := map[string][]byte{}
	matchID := ""
	for _, c := range codes {
		h, err := parseArgon2idHash(c.CodeHash)
		if err != nil {
			continue // corrupted row: never matches
		}
		cacheKey := fmt.Sprintf("%d/%d/%d/%x/%d", h.memory, h.iterations, h.parallelism, h.salt, len(h.key))
		got, ok := computed[cacheKey]
		if !ok {
			got = argon2.IDKey([]byte(norm), h.salt, h.iterations, h.memory, h.parallelism, uint32(len(h.key)))
			computed[cacheKey] = got
		}
		// No early exit: always compare against every stored code.
		if subtle.ConstantTimeCompare(got, h.key) == 1 && matchID == "" {
			matchID = c.ID
		}
	}
	if matchID == "" {
		return false, nil
	}
	consumed, err := s.codes.ConsumeIfUnused(ctx, matchID)
	if err != nil {
		return false, fmt.Errorf("verify backup code: %w", err)
	}
	return consumed, nil
}
