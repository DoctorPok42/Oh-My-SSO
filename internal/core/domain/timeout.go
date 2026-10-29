package domain

import "time"

type TimeoutTargetType string

const (
	TimeoutTargetUser      TimeoutTargetType = "user"
	TimeoutTargetGroup     TimeoutTargetType = "group"
	TimeoutTargetClientApp TimeoutTargetType = "client"
)

// Valid reports whether t is one of the three target types.
func (t TimeoutTargetType) Valid() bool {
	switch t {
	case TimeoutTargetUser, TimeoutTargetGroup, TimeoutTargetClientApp:
		return true
	}
	return false
}

// Timeout is a temporary suspension set by an administrator. While it is in
// force, the user it targets (directly, or through one of their groups)
// cannot sign in or get a token, and nobody can sign in to the client it
// targets.
type Timeout struct {
	ID         string
	RealmID    string
	TargetType TimeoutTargetType
	TargetID   string
	StartsAt   time.Time
	EndsAt     time.Time // zero: no end, until lifted
	Reason     string
	CreatedBy  string // "user:<id>" (admin console), "cli:<os user>"
	CreatedAt  time.Time
	LiftedAt   time.Time // zero: not lifted
	LiftedBy   string
	// EnforcedAt: when the targets were signed out, at the start. Zero: not
	// done yet (scheduled, or the enforcer has not run yet).
	EnforcedAt time.Time
}

type TimeoutStatus string

const (
	TimeoutScheduled TimeoutStatus = "scheduled" // starts later
	TimeoutActive    TimeoutStatus = "active"    // in force
	TimeoutEnded     TimeoutStatus = "ended"     // reached its end
	TimeoutLifted    TimeoutStatus = "lifted"    // ended early (or cancelled before its start) by an administrator
)

// InForceAt reports whether the timeout blocks its targets at time at.
func (t *Timeout) InForceAt(at time.Time) bool {
	return !at.Before(t.StartsAt) && (t.EndsAt.IsZero() || at.Before(t.EndsAt))
}

// StatusAt is the status shown to administrators at time at.
func (t *Timeout) StatusAt(at time.Time) TimeoutStatus {
	switch {
	case !t.LiftedAt.IsZero():
		return TimeoutLifted
	case at.Before(t.StartsAt):
		return TimeoutScheduled
	case t.EndsAt.IsZero() || at.Before(t.EndsAt):
		return TimeoutActive
	}
	return TimeoutEnded
}

// Over reports whether the timeout can no longer be in force (lifted, or
// past its end): it cannot be changed any more.
func (t *Timeout) Over(at time.Time) bool {
	s := t.StatusAt(at)
	return s == TimeoutLifted || s == TimeoutEnded
}

// OnPeople reports whether the timeout is on people (a user or a group), as
// opposed to an application.
func (t *Timeout) OnPeople() bool { return t.TargetType != TimeoutTargetClientApp }
