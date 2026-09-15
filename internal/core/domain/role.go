package domain

import "time"

type RoleStatus string

const (
	RoleActive   RoleStatus = "active"
	RoleInactive RoleStatus = "inactive"
)

type RoleManagedBy string

const (
	RoleManagedByUI     RoleManagedBy = "ui"
	RoleManagedByConfig RoleManagedBy = "config"
)

type Role struct {
	ID          string
	RealmID     string
	ManagedBy   RoleManagedBy
	Name        string
	Description string
	Status      RoleStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
