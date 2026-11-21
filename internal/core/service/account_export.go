package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// A copy of the user's data (GDPR articles 15 and 20). The account console's
// "Your data" page asks for it; it is made in the background, the user gets
// an e-mail once it is ready, and downloading it asks "Confirm it's you"
// again. It is deleted DataExportTTL after it was made (PurgeService).

const (
	// DataExportTTL: how long a copy can be downloaded.
	DataExportTTL = 7 * 24 * time.Hour
	// dataExportStale: a copy still being made after that lost its server
	// (stopped during the work): it shows as failed, and a new request
	// replaces it.
	dataExportStale = 15 * time.Minute
	// dataExportWork bounds the reads of one copy.
	dataExportWork = 5 * time.Minute
	// dataExportFinish bounds saving its end (ready or failed).
	dataExportFinish = 10 * time.Second
	// dataExportPage: rows per query of the sign-in history and the audit log.
	dataExportPage = 500
	// shortcut: past dataExportMaxRows sign-ins or audit entries the copy
	// keeps the newest and lists the cut list in "truncated"; build the
	// document as a stream if accounts ever get that many.
	dataExportMaxRows = 10000
	// DataExportFormat names the layout of the document.
	DataExportFormat = "omsso.personal-data.v1"
)

var (
	ErrDataExportRunning  = errors.New("service: a copy of the data is already being made")
	ErrDataExportNotReady = errors.New("service: no copy of the data to download")
	ErrDataExportStopping = errors.New("service: the server is stopping")
)

// DataExportEnabled tells whether the account console offers the copy.
func (s *AccountService) DataExportEnabled() bool { return s.d.DataExports != nil }

// RequestDataExport starts a copy of the user's data in the background; it
// replaces the previous copy, unless one is still being made.
func (s *AccountService) RequestDataExport(ctx context.Context, realm *domain.Realm, user *domain.User, ev AccountEvent) (*domain.DataExport, error) {
	if s.d.DataExports == nil {
		return nil, ErrDataExportNotReady
	}
	if !s.exports.begin() {
		return nil, ErrDataExportStopping
	}
	now := s.d.Now()
	e := &domain.DataExport{RealmID: user.RealmID, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(DataExportTTL)}
	if err := s.d.DataExports.Start(ctx, e, now.Add(-dataExportStale)); err != nil {
		s.exports.wg.Done()
		if errors.Is(err, repository.ErrConflict) {
			return nil, ErrDataExportRunning
		}
		return nil, fmt.Errorf("data export: %w", err)
	}
	s.audit(ctx, user, audit.UserDataExportRequested, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev, nil)
	go s.runDataExport(e, realm, user.ID)
	return e, nil
}

// runDataExport makes one copy. It owns one s.exports.wg slot. The reads
// ignore the server's stop: they are short, and the stop waits for them.
func (s *AccountService) runDataExport(e *domain.DataExport, realm *domain.Realm, userID string) {
	defer s.exports.wg.Done()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.exports.ctx), dataExportWork)
	defer cancel()
	status, data := domain.DataExportFailed, []byte(nil)
	defer func() {
		if r := recover(); r != nil {
			s.d.Logger.Error("data export: panic", "user_id", userID, "panic", r)
			status, data = domain.DataExportFailed, nil
		}
		// Its own budget: the work may have used all of ctx's, and an end
		// not saved leaves the copy "being made" until it is stale.
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), dataExportFinish)
		defer fcancel()
		s.finishDataExport(fctx, e, status, data)
	}()
	doc, err := s.buildDataExport(ctx, realm, userID)
	if err == nil {
		data, err = json.MarshalIndent(doc, "", "  ")
	}
	if err != nil {
		s.d.Logger.Error("data export: failed", "user_id", userID, "error", err)
		return
	}
	status = domain.DataExportReady
}

func (s *AccountService) finishDataExport(ctx context.Context, e *domain.DataExport, status domain.DataExportStatus, data []byte) {
	now := s.d.Now()
	expires := now.Add(DataExportTTL)
	if err := s.d.DataExports.Finish(ctx, e.ID, status, data, now, expires); err != nil {
		s.d.Logger.Error("data export: end not saved", "user_id", e.UserID, "error", err)
		return
	}
	if status != domain.DataExportReady {
		return
	}
	s.d.Notifier.Notify(ctx, domain.NotificationEvent{
		Kind: domain.NotificationDataExportReady, RealmID: e.RealmID, UserID: e.UserID,
		OccurredAt: now, ExpiresAt: expires,
	})
}

// StopDataExports refuses new copies and waits for the ones being made,
// until ctx ends.
func (s *AccountService) StopDataExports(ctx context.Context) {
	if !s.exports.stop(ctx) {
		s.d.Logger.Warn("data exports: stopped waiting for the copies being made")
	}
}

// DataExport returns the user's copy, nil when there is none or it
// expired. A copy still being made after dataExportStale shows as failed.
func (s *AccountService) DataExport(ctx context.Context, user *domain.User) (*domain.DataExport, error) {
	if s.d.DataExports == nil {
		return nil, nil
	}
	e, err := s.d.DataExports.GetByUser(ctx, user.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("data export: %w", err)
	}
	now := s.d.Now()
	if !now.Before(e.ExpiresAt) {
		return nil, nil
	}
	if e.Status == domain.DataExportRunning && now.Sub(e.CreatedAt) > dataExportStale {
		e.Status = domain.DataExportFailed
	}
	return e, nil
}

// DownloadDataExport returns the user's copy, ready, and records the
// download.
func (s *AccountService) DownloadDataExport(ctx context.Context, user *domain.User, ev AccountEvent) (*domain.DataExport, error) {
	e, err := s.DataExport(ctx, user)
	if err != nil {
		return nil, err
	}
	if e == nil || e.Status != domain.DataExportReady {
		return nil, ErrDataExportNotReady
	}
	e.Data, err = s.d.DataExports.GetData(ctx, e.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrDataExportNotReady // replaced or purged a moment ago
	}
	if err != nil {
		return nil, fmt.Errorf("data export: %w", err)
	}
	s.audit(ctx, user, audit.UserDataExported, "User", user.ID, domain.AuditLogInfo, domain.AuditLogSuccess, ev,
		map[string]interface{}{"made_at": e.CreatedAt.UTC().Format(time.RFC3339)})
	return e, nil
}

// --- the document -----------------------------------------------------------

// dataExportDoc is what the server keeps about the user, without what only
// proves who they are: password hashes, second-factor secrets, backup
// codes, tokens.
type dataExportDoc struct {
	Format         string           `json:"format"`
	ExportedAt     time.Time        `json:"exported_at"`
	Organization   exportOrg        `json:"organization"`
	Account        exportAccount    `json:"account"`
	Groups         []string         `json:"groups"`
	Roles          []string         `json:"roles"`
	SecondFactors  []exportFactor   `json:"second_factors"`
	Sessions       []AccountSession `json:"sessions"`
	Applications   []AccountApp     `json:"applications"`
	TrustedDevices []exportDevice   `json:"trusted_devices"`
	SignIns        []SignInEntry    `json:"sign_ins"`
	Activity       []ActivityEntry  `json:"activity"`
	Truncated      []string         `json:"truncated,omitempty"` // lists cut at dataExportMaxRows, newest kept
}

type exportOrg struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
}

type exportAccount struct {
	ID                 string                 `json:"id"`
	Username           string                 `json:"username"`
	Email              string                 `json:"email"`
	EmailVerifiedAt    *time.Time             `json:"email_verified_at,omitempty"`
	PendingEmail       string                 `json:"pending_email,omitempty"`
	Status             domain.UserStatus      `json:"status"`
	Profile            map[string]interface{} `json:"profile,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	LastLoginAt        *time.Time             `json:"last_login_at,omitempty"`
	PasswordChangedAt  time.Time              `json:"password_changed_at,omitzero"`
	MustChangePassword bool                   `json:"must_change_password"`
}

type exportFactor struct {
	Type       domain.MfaMethodType   `json:"type"`
	Name       string                 `json:"name,omitempty"`
	Status     domain.MfaMethodStatus `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	LastUsedAt time.Time              `json:"last_used_at,omitzero"`
}

type exportDevice struct {
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

func (s *AccountService) buildDataExport(ctx context.Context, realm *domain.Realm, userID string) (*dataExportDoc, error) {
	user, err := s.d.Users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	doc := &dataExportDoc{
		Format: DataExportFormat, ExportedAt: s.d.Now().UTC(),
		Organization: exportOrg{Name: realm.Name, DisplayName: realm.DisplayName},
		Account: exportAccount{
			ID: user.ID, Username: user.Username, Email: user.Email, EmailVerifiedAt: user.EmailVerifiedAt, PendingEmail: user.PendingEmail,
			Status: user.Status, Profile: user.Profile, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
			LastLoginAt: user.LastLoginAt, PasswordChangedAt: user.PasswordChangedAt, MustChangePassword: user.MustChangePassword,
		},
		Groups: []string{}, Roles: []string{}, SecondFactors: []exportFactor{}, TrustedDevices: []exportDevice{},
	}

	m, err := s.d.Admin.Memberships(ctx, []string{user.ID})
	if err != nil {
		return nil, fmt.Errorf("memberships: %w", err)
	}
	for _, id := range m[user.ID].GroupIDs {
		doc.Groups = append(doc.Groups, m[user.ID].Names[id])
	}
	for _, id := range m[user.ID].RoleIDs {
		doc.Roles = append(doc.Roles, m[user.ID].Names[id])
	}

	if s.d.MFAMethods != nil {
		methods, err := s.d.MFAMethods.ListByUser(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("second factors: %w", err)
		}
		for _, f := range methods {
			doc.SecondFactors = append(doc.SecondFactors, exportFactor{
				Type: f.Type, Name: f.Name, Status: f.Status, CreatedAt: f.CreatedAt, LastUsedAt: f.LastUsedAt,
			})
		}
	}

	if doc.Sessions, err = s.Sessions(ctx, user, ""); err != nil {
		return nil, fmt.Errorf("sessions: %w", err)
	}
	if doc.Applications, err = s.Apps(ctx, user); err != nil {
		return nil, fmt.Errorf("applications: %w", err)
	}
	devices, err := s.TrustedDevices(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("trusted devices: %w", err)
	}
	for _, d := range devices {
		doc.TrustedDevices = append(doc.TrustedDevices, exportDevice{
			IPAddress: d.IPAddress, UserAgent: d.UserAgent, CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, LastUsedAt: d.LastUsedAt,
		})
	}

	signIns, cut, err := allPages(func(offset, limit int) ([]SignInEntry, bool, error) { return s.SignIns(ctx, user, offset, limit) })
	if err != nil {
		return nil, err
	}
	if doc.SignIns = signIns; cut {
		doc.Truncated = append(doc.Truncated, "sign_ins")
	}
	activity, cut, err := allPages(func(offset, limit int) ([]ActivityEntry, bool, error) {
		return s.activity(ctx, user, nil, offset, limit)
	})
	if err != nil {
		return nil, err
	}
	if doc.Activity = activity; cut {
		doc.Truncated = append(doc.Truncated, "activity")
	}
	return doc, nil
}

// allPages reads pages of dataExportPage rows until the last one, or
// dataExportMaxRows rows (cut: true). Never nil.
func allPages[T any](read func(offset, limit int) ([]T, bool, error)) ([]T, bool, error) {
	out := []T{}
	for offset := 0; ; offset += dataExportPage {
		rows, more, err := read(offset, dataExportPage)
		if err != nil {
			return nil, false, err
		}
		out = append(out, rows...)
		if len(out) >= dataExportMaxRows {
			return out[:dataExportMaxRows], more || len(out) > dataExportMaxRows, nil
		}
		if !more {
			return out, false, nil
		}
	}
}
