package service

import (
	"context"
	"maps"

	"sso.internal/sso/internal/core/audit"
	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/core/repository"
)

// BatchedAuditLog wraps the audit log so that a bulk action leaves one
// entry: inside a bulk action (audit.BatchOf), every entry written by any
// service is handed to the batch instead, and the bulk runner writes them
// as a whole at the end. Outside one, or once the batch is closed, entries
// are written as usual (with the operation id when there is one).
func BatchedAuditLog(next repository.AuditLogRepository) repository.AuditLogRepository {
	if next == nil {
		return nil
	}
	if _, ok := next.(batchedAuditLog); ok {
		return next
	}
	return batchedAuditLog{next}
}

type batchedAuditLog struct {
	repository.AuditLogRepository
}

// batchNoise: details every admin entry repeats, that the bulk entry holds
// once.
var batchNoise = []string{"admin_realm", "admin_username", "operation_id"}

func (r batchedAuditLog) Create(ctx context.Context, p repository.CreateAuditLogParams) (*domain.AuditLog, error) {
	b := audit.BatchOf(ctx)
	if b == nil {
		return r.AuditLogRepository.Create(ctx, p)
	}
	details := maps.Clone(p.Details)
	for _, k := range batchNoise {
		delete(details, k)
	}
	if len(details) == 0 {
		details = nil
	}
	target := p.TargetUserID
	if target == "" && p.ResourceType == "User" {
		target = p.ResourceID
	}
	if b.Add(audit.Entry{
		Action: p.Action, ResourceType: p.ResourceType, ResourceID: p.ResourceID, TargetUserID: target,
		Warning: (p.Level != domain.AuditLogInfo && p.Level != domain.AuditLogDebug && p.Level != "") || p.Status == domain.AuditLogFailure,
		Details: details,
	}) {
		return &domain.AuditLog{RealmID: p.RealmID, Action: p.Action}, nil
	}
	if p.Details == nil || p.Details["operation_id"] == nil {
		p.Details = maps.Clone(p.Details)
		if p.Details == nil {
			p.Details = map[string]interface{}{}
		}
		p.Details["operation_id"] = b.Operation()
	}
	return r.AuditLogRepository.Create(ctx, p)
}
