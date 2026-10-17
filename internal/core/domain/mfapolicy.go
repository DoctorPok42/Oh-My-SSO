package domain

import "time"

type MfaPolicyManagedBy string

const (
	MfaPolicyManagedByUI     MfaPolicyManagedBy = "ui"
	MfaPolicyManagedByConfig MfaPolicyManagedBy = "config"
)

// MfaPolicy is the MFA policy of one Role. See ent/schema/mfapolicy.go.
type MfaPolicy struct {
	ID        string
	RealmID   string
	RoleID    string
	ManagedBy MfaPolicyManagedBy

	Required                  bool
	AllowedMethods            []MfaMethodType // empty: any method
	EnrollmentGraceDays       int
	StepUpForSensitiveActions bool
	RequiredSince             time.Time // zero when Required is false

	CreatedAt time.Time
	UpdatedAt time.Time
}
