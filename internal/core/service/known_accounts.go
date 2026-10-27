package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"sso.internal/sso/internal/core"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// "Pick an account" (Step 18b). An account is remembered on a device when
// the user signs in there with "Keep me signed in" ticked. It then stays in
// the picker after sign-outs, until the user clicks "Forget" (or the
// account is deleted). A device is the sso_device cookie, one per realm.

// MaxKnownAccountsPerDevice: beyond it, the least recently used account of
// the device is dropped.
const MaxKnownAccountsPerDevice = 10

var ErrKnownAccountNotFound = errors.New("service: known account not found")

type KnownAccountService struct {
	accounts repository.KnownAccountRepository
	users    repository.UserRepository
	audit    repository.AuditLogRepository // nil: "Forget" is not audited
	now      func() time.Time
	logger   *slog.Logger
}

type KnownAccountDeps struct {
	Accounts repository.KnownAccountRepository
	Users    repository.UserRepository
	Audit    repository.AuditLogRepository
	Now      func() time.Time
	Logger   *slog.Logger
}

func NewKnownAccountService(d KnownAccountDeps) *KnownAccountService {
	s := &KnownAccountService{accounts: d.Accounts, users: d.Users, audit: d.Audit, now: d.Now, logger: d.Logger}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s
}

// SessionCreated (LoginObserver) remembers the account of a new remembered
// session on its device. A sign-in without "Keep me signed in" adds
// nothing and removes nothing. A failure only costs the tile: it is logged.
func (s *KnownAccountService) SessionCreated(ctx context.Context, sess *domain.Session) {
	if !sess.RememberMe || sess.DeviceFingerprint == "" {
		return
	}
	if _, err := s.accounts.Touch(ctx, sess.RealmID, sess.DeviceFingerprint, sess.UserID, s.now()); err != nil {
		s.logger.WarnContext(ctx, "known accounts: remember", "session_id", sess.ID, "error", err)
		return
	}
	if _, err := s.accounts.Trim(ctx, sess.RealmID, sess.DeviceFingerprint, MaxKnownAccountsPerDevice); err != nil {
		s.logger.WarnContext(ctx, "known accounts: trim", "session_id", sess.ID, "error", err)
	}
}

// List returns the accounts to show on a device (core.IdentityCore.KnownAccounts).
func (s *KnownAccountService) List(ctx context.Context, q core.AccountQuery) ([]core.Account, error) {
	var out []core.Account
	currentUser := ""
	if q.Current != nil && q.Current.RealmID == q.RealmID {
		if u, ok := s.showable(ctx, q.RealmID, q.Current.UserID); ok {
			acc := AccountOf(u)
			acc.SignedIn = true
			out = append(out, acc)
			currentUser = u.ID
		}
	}

	hash := deviceHash(q.DeviceID)
	if hash == "" {
		return out, nil
	}
	rows, err := s.accounts.ListByDevice(ctx, q.RealmID, hash)
	if err != nil {
		return nil, fmt.Errorf("known accounts: list: %w", err)
	}
	for _, row := range rows {
		if row.UserID == currentUser {
			out[0].ID = row.ID // the current account is remembered too
			continue
		}
		u, ok := s.showable(ctx, q.RealmID, row.UserID)
		if !ok {
			continue
		}
		acc := AccountOf(u)
		acc.ID = row.ID
		out = append(out, acc)
	}
	return out, nil
}

// ForgetInput: "Forget" on a tile.
type ForgetAccountInput struct {
	RealmID   string
	DeviceID  string // raw sso_device cookie of the browser that asks
	AccountID string
	IPAddress string
	UserAgent string
}

// Forget removes an account from the picker of a device. Only the device
// that shows it can remove it: an id from another device (or realm) is
// ErrKnownAccountNotFound, like an unknown one. The caller signs the
// account out too when it is the browser's current one.
func (s *KnownAccountService) Forget(ctx context.Context, in ForgetAccountInput) (*domain.KnownAccount, error) {
	hash := deviceHash(in.DeviceID)
	if hash == "" || in.AccountID == "" {
		return nil, ErrKnownAccountNotFound
	}
	row, err := s.accounts.GetByID(ctx, in.AccountID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrKnownAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("known accounts: forget: %w", err)
	}
	if row.RealmID != in.RealmID || row.DeviceHash != hash {
		return nil, ErrKnownAccountNotFound
	}
	if err := s.accounts.Delete(ctx, row.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrKnownAccountNotFound
		}
		return nil, fmt.Errorf("known accounts: forget: %w", err)
	}
	if s.audit != nil {
		if _, err := s.audit.Create(ctx, repository.CreateAuditLogParams{
			RealmID: row.RealmID, UserID: row.UserID, Action: "known_account.forget",
			ResourceType: "KnownAccount", ResourceID: row.ID, IPAddress: in.IPAddress, UserAgent: in.UserAgent,
			Level: domain.AuditLogInfo, Status: domain.AuditLogSuccess,
		}); err != nil {
			s.logger.WarnContext(ctx, "audit: record forget", "known_account_id", row.ID, "error", err)
		}
	}
	return row, nil
}

// showable: the user exists, belongs to the realm and is active. A
// suspended or deleted account never shows on the sign-in page.
func (s *KnownAccountService) showable(ctx context.Context, realmID, userID string) (*domain.User, bool) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			s.logger.WarnContext(ctx, "known accounts: load user", "user_id", userID, "error", err)
		}
		return nil, false
	}
	return u, u.RealmID == realmID && u.Status == domain.UserActive
}

// AccountOf describes a user for the sign-in page (ID and SignedIn unset).
func AccountOf(u *domain.User) core.Account {
	name := strings.TrimSpace(profileString(u, "given_name") + " " + profileString(u, "family_name"))
	if name == "" {
		name = profileString(u, "name")
	}
	if name == "" {
		name = u.Username
	}
	id := u.Email
	if id == "" {
		id = u.Username
	}
	return core.Account{Name: name, Email: u.Email, Username: u.Username, Identifier: id}
}

func profileString(u *domain.User, key string) string {
	v, _ := u.Profile[key].(string)
	return strings.TrimSpace(v)
}

// IsDeviceID tells whether v has the format of the ids we put in the
// sso_device cookie (crypto/rand.Text: 26 characters of base32), so a
// crafted cookie cannot inject anything.
func IsDeviceID(v string) bool {
	if len(v) != 26 {
		return false
	}
	for _, ch := range v {
		if !(ch >= 'A' && ch <= 'Z') && !(ch >= '2' && ch <= '7') {
			return false
		}
	}
	return true
}

// deviceHash is what known_accounts stores for a raw device id ("" for a
// missing or malformed one).
func deviceHash(deviceID string) string {
	if !IsDeviceID(deviceID) {
		return ""
	}
	return DeviceFingerprint(deviceID)
}
