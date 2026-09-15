package domain

import "time"

type AuditLogLevel string

const (
	AuditLogDebug      AuditLogLevel = "debug"
	AuditLogSuspicious AuditLogLevel = "suspicious"
	AuditLogInfo       AuditLogLevel = "info"
	AuditLogWarning    AuditLogLevel = "warning"
	AuditLogError      AuditLogLevel = "error"
	AuditLogCritical   AuditLogLevel = "critical"
)

type AuditLogStatus string

const (
	AuditLogSuccess AuditLogStatus = "success"
	AuditLogFailure AuditLogStatus = "failure"
)

type AuditLog struct {
	ID           string
	RealmID      string
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	Timestamp    time.Time
	IPAddress    string
	UserAgent    string
	Level        AuditLogLevel
	Status       AuditLogStatus
	Details      map[string]interface{}
}
