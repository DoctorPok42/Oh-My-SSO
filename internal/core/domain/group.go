package domain

import "time"

type GroupStatus string

const (
	GroupActive   GroupStatus = "active"
	GroupInactive GroupStatus = "inactive"
)

type GroupManagedBy string

const (
	GroupManagedByUI     GroupManagedBy = "ui"
	GroupManagedByConfig GroupManagedBy = "config"
)

type Group struct {
	ID          string
	RealmID     string
	ManagedBy   GroupManagedBy
	Name        string
	Description string
	Status      GroupStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
