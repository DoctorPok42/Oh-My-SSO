package domain

import (
	"strings"
	"time"
)

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

// AuditActorType tells who did an action. UserID is the actor's id when
// the actor is a person (user or admin); the user the action is about is
// TargetUserID.
type AuditActorType string

const (
	AuditActorUser      AuditActorType = "user"      // a user of the realm, on their own account
	AuditActorAdmin     AuditActorType = "admin"     // an administrator (admin console)
	AuditActorCLI       AuditActorType = "cli"       // an operator on the command line
	AuditActorSystem    AuditActorType = "system"    // the server itself (lockout, key retirer, e-mails...)
	AuditActorAnonymous AuditActorType = "anonymous" // nobody signed in (a failed sign-in)
)

func (t AuditActorType) Valid() bool {
	switch t {
	case AuditActorUser, AuditActorAdmin, AuditActorCLI, AuditActorSystem, AuditActorAnonymous:
		return true
	}
	return false
}

// AuditActorFromTrigger reads the "triggered_by" strings the services pass
// around ("user:<id>", "cli:<os user>", "system:<what>"). A "user:" id is
// an administrator unless it is targetUserID (a user acting on their own
// account).
func AuditActorFromTrigger(triggeredBy, targetUserID string) (AuditActorType, string) {
	switch {
	case strings.HasPrefix(triggeredBy, "user:"):
		id := strings.TrimPrefix(triggeredBy, "user:")
		if id != "" && id == targetUserID {
			return AuditActorUser, id
		}
		return AuditActorAdmin, id
	case triggeredBy == "cli" || strings.HasPrefix(triggeredBy, "cli:"):
		return AuditActorCLI, ""
	default:
		return AuditActorSystem, ""
	}
}

type AuditLog struct {
	ID           string
	RealmID      string
	UserID       string // the actor, when a person
	ActorType    AuditActorType
	TargetUserID string // the user the action is about
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
