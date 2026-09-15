package domain

import "time"

type TimeoutTargetType string

const (
	TimeoutTargetUser      TimeoutTargetType = "user"
	TimeoutTargetGroup     TimeoutTargetType = "group"
	TimeoutTargetClientApp TimeoutTargetType = "client"
)

type Timeout struct {
	ID         string
	RealmID    string
	TargetType TimeoutTargetType
	TargetID   string
	StartsAt   time.Time
	EndsAt     time.Time
	Reason     string
	CreatedBy  string
	CreatedAt  time.Time
}
