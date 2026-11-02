package service

import (
	"context"
	"log/slog"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// AuditedLoginAttempts records every failed sign-in in the audit log too
// (auth.login_failed, or auth.mfa_failed for a wrong second factor), on top
// of the LoginAttempt row the account console's "History" page reads.
//
// The actor is anonymous: whoever typed the password is not signed in, and
// may not be the account's owner. The account, when it exists, is the
// target. Successful sign-ins are recorded once the session exists
// (LoginSecurityService: auth.login, auth.login_new_device...).
func AuditedLoginAttempts(next repository.LoginAttemptRepository, log repository.AuditLogRepository, logger *slog.Logger) repository.LoginAttemptRepository {
	if log == nil {
		return next
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &auditedLoginAttempts{LoginAttemptRepository: next, audit: log, logger: logger}
}

type auditedLoginAttempts struct {
	repository.LoginAttemptRepository
	audit  repository.AuditLogRepository
	logger *slog.Logger
}

func (r *auditedLoginAttempts) Create(ctx context.Context, p repository.CreateLoginAttemptParams) (*domain.LoginAttempt, error) {
	a, err := r.LoginAttemptRepository.Create(ctx, p)
	if p.Status != domain.LoginAttemptFailure {
		return a, err
	}
	action, level := audit.AuthLoginFailed, domain.AuditLogInfo
	switch p.FailureReason {
	case domain.LoginFailureMfaFailed:
		action, level = audit.AuthMFAFailed, domain.AuditLogWarning
	case domain.LoginFailureAccountLocked, domain.LoginFailureTimeoutActive, domain.LoginFailurePasskeyRejected:
		level = domain.AuditLogWarning
	}
	details := map[string]interface{}{"reason": string(p.FailureReason)}
	if p.Identifier != "" {
		details["identifier"] = p.Identifier
	}
	resourceType := ""
	if p.UserID != "" {
		resourceType = "User"
	}
	if _, aerr := r.audit.Create(ctx, repository.CreateAuditLogParams{
		RealmID:      p.RealmID,
		ActorType:    domain.AuditActorAnonymous,
		TargetUserID: p.UserID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   p.UserID,
		IPAddress:    p.IPAddress,
		UserAgent:    p.UserAgent,
		Level:        level,
		Status:       domain.AuditLogFailure,
		Details:      details,
	}); aerr != nil {
		r.logger.WarnContext(ctx, "audit: failed sign-in", "realm_id", p.RealmID, "error", aerr)
	}
	return a, err
}
