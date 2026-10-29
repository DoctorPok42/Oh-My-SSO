package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// "Don't ask again on this device" (Step 18d).
//
// After a second factor, the user may tick the box: the device (the
// sso_device cookie of Step 18b) becomes trusted for the realm's
// mfa_trusted_device_days. There, a password alone signs them in again,
// as long as no policy requires MFA for the sign-in and the sign-in does
// not look suspicious (MFAService.BeginLogin). Such a session is never
// MFA-verified: an application that requires MFA still asks (step-up).
//
// The trust ends at its expiry (fixed: using it does not extend it), with
// "Forget" on the device's tile, and whenever every session of the user is
// revoked (password reset, MFA reset, an admin, a suspension).

const (
	DefaultTrustedDeviceDays = 30
	MinTrustedDeviceDays     = 1
	MaxTrustedDeviceDays     = 90
)

// Reasons a trust ends early (audit details).
const (
	TrustRevokedForget = "forget"
	TrustRevokedAdmin  = "admin"
)

var ErrTrustedDeviceNotFound = errors.New("service: trusted device not found")

type TrustedDeviceService struct {
	devices  repository.TrustedDeviceRepository
	settings repository.InstanceSettingsRepository
	audit    repository.AuditLogRepository
	now      func() time.Time
	logger   *slog.Logger
}

type TrustedDeviceDeps struct {
	Devices  repository.TrustedDeviceRepository
	Settings repository.InstanceSettingsRepository // nil: the defaults
	Audit    repository.AuditLogRepository         // optional
	Now      func() time.Time                      // optional (tests)
	Logger   *slog.Logger                          // optional
}

func NewTrustedDeviceService(d TrustedDeviceDeps) *TrustedDeviceService {
	s := &TrustedDeviceService{devices: d.Devices, settings: d.Settings, audit: d.Audit, now: d.Now, logger: d.Logger}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s
}

// Policy tells whether a realm offers the box, and for how long. A realm
// without settings has the defaults (on, 30 days). The settings cannot be
// read: off (a second factor is asked, never skipped by mistake).
func (s *TrustedDeviceService) Policy(ctx context.Context, realmID string) (bool, time.Duration) {
	days := DefaultTrustedDeviceDays
	if s.settings != nil {
		st, err := s.settings.GetByRealmID(ctx, realmID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
		case err != nil:
			s.logger.WarnContext(ctx, "trusted devices: cannot read realm settings, off", "realm_id", realmID, "error", err)
			return false, 0
		case !st.MFATrustedDeviceEnabled:
			return false, 0
		default:
			days = st.MFATrustedDeviceDays
		}
	}
	return true, time.Duration(clampTrustedDeviceDays(days)) * 24 * time.Hour
}

func clampTrustedDeviceDays(days int) int {
	switch {
	case days <= 0:
		return DefaultTrustedDeviceDays
	case days > MaxTrustedDeviceDays:
		return MaxTrustedDeviceDays
	}
	return days
}

// Trust records the box ticked after a second factor. It does nothing when
// the realm does not offer it or the browser has no device cookie.
func (s *TrustedDeviceService) Trust(ctx context.Context, user *domain.User, deviceHash, ip, userAgent string) (*domain.TrustedDevice, error) {
	on, period := s.Policy(ctx, user.RealmID)
	if !on || deviceHash == "" {
		return nil, nil
	}
	now := s.now()
	if _, err := s.devices.DeleteExpired(ctx, user.ID, now); err != nil {
		s.logger.WarnContext(ctx, "trusted devices: clean up", "user_id", user.ID, "error", err)
	}
	d, err := s.devices.Put(ctx, repository.PutTrustedDeviceParams{
		RealmID: user.RealmID, UserID: user.ID, DeviceHash: deviceHash,
		IPAddress: ip, UserAgent: userAgent, CreatedAt: now, ExpiresAt: now.Add(period),
	})
	if err != nil {
		return nil, fmt.Errorf("trust device: %w", err)
	}
	s.record(ctx, user.RealmID, user.ID, "mfa_device_trusted", d.ID, ip, userAgent, map[string]interface{}{
		"days": int(period / (24 * time.Hour)), "expires_at": d.ExpiresAt.UTC().Format(time.RFC3339),
	})
	return d, nil
}

// Check returns the trust of user on a device when it still holds (the
// realm must still offer it).
func (s *TrustedDeviceService) Check(ctx context.Context, user *domain.User, deviceHash string) (*domain.TrustedDevice, bool, error) {
	if deviceHash == "" {
		return nil, false, nil
	}
	if on, _ := s.Policy(ctx, user.RealmID); !on {
		return nil, false, nil
	}
	d, err := s.devices.Get(ctx, user.ID, deviceHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("trusted device: %w", err)
	}
	if d.RealmID != user.RealmID || !d.Active(s.now()) {
		return nil, false, nil
	}
	return d, true, nil
}

// Used records a sign-in that skipped the second factor. A failure only
// costs the date: it is logged.
func (s *TrustedDeviceService) Used(ctx context.Context, d *domain.TrustedDevice, ip, userAgent string) {
	if err := s.devices.MarkUsed(ctx, d.ID, s.now(), ip, userAgent); err != nil {
		s.logger.WarnContext(ctx, "trusted devices: mark used", "trusted_device_id", d.ID, "error", err)
	}
}

// List returns the devices a user trusts now, most recent first.
func (s *TrustedDeviceService) List(ctx context.Context, userID string) ([]*domain.TrustedDevice, error) {
	return s.devices.ListByUser(ctx, userID, s.now())
}

// RevokeDevice ends the trust of a device ("Forget" on its tile).
func (s *TrustedDeviceService) RevokeDevice(ctx context.Context, realmID, userID, deviceHash, reason string) error {
	n, err := s.devices.DeleteByDevice(ctx, userID, deviceHash)
	if err != nil {
		return fmt.Errorf("revoke trusted device: %w", err)
	}
	if n > 0 {
		s.record(ctx, realmID, userID, "mfa_device_trust_revoked", "", "", "", map[string]interface{}{"reason": reason, "devices": n})
	}
	return nil
}

// AllSessionsRevoked (RevocationObserver): every session of the user was
// revoked, their trusted devices go too.
func (s *TrustedDeviceService) AllSessionsRevoked(ctx context.Context, userID string, reason domain.SessionRevokedReason) {
	rows, err := s.devices.ListByUser(ctx, userID, time.Time{}) // expired ones too
	if err != nil {
		s.logger.WarnContext(ctx, "trusted devices: revoke all", "user_id", userID, "error", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	n, err := s.devices.DeleteByUser(ctx, userID)
	if err != nil {
		s.logger.WarnContext(ctx, "trusted devices: revoke all", "user_id", userID, "error", err)
		return
	}
	s.record(ctx, rows[0].RealmID, userID, "mfa_device_trust_revoked", "", "", "", map[string]interface{}{
		"reason": string(reason), "devices": n,
	})
}

// RevokeOne ends one trust of a user (an admin; the admin audit entry is
// the caller's).
func (s *TrustedDeviceService) RevokeOne(ctx context.Context, userID, id string) error {
	rows, err := s.devices.ListByUser(ctx, userID, time.Time{})
	if err != nil {
		return fmt.Errorf("revoke trusted device: %w", err)
	}
	for _, d := range rows {
		if d.ID == id {
			if err := s.devices.Delete(ctx, id); err != nil && !errors.Is(err, repository.ErrNotFound) {
				return fmt.Errorf("revoke trusted device: %w", err)
			}
			return nil
		}
	}
	return ErrTrustedDeviceNotFound
}

// RevokeAll ends every trust of a user (an admin) and returns how many.
func (s *TrustedDeviceService) RevokeAll(ctx context.Context, userID string) (int, error) {
	n, err := s.devices.DeleteByUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke trusted devices: %w", err)
	}
	return n, nil
}

func (s *TrustedDeviceService) record(ctx context.Context, realmID, userID, action, id, ip, userAgent string, details map[string]interface{}) {
	if s.audit == nil {
		return
	}
	level := domain.AuditLogInfo
	if action == "mfa_device_trust_revoked" {
		level = domain.AuditLogWarning
	}
	if _, err := s.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID: realmID, UserID: userID, Action: action, ResourceType: "TrustedDevice", ResourceID: id,
		IPAddress: ip, UserAgent: userAgent, Level: level, Status: domain.AuditLogSuccess, Details: details,
	}); err != nil {
		s.logger.WarnContext(ctx, "audit: trusted device", "action", action, "user_id", userID, "error", err)
	}
}
