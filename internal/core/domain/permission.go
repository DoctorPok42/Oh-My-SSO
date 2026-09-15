package domain

import "time"

type PermissionStatus string

const (
	PermissionActive   PermissionStatus = "active"
	PermissionInactive PermissionStatus = "inactive"
)

type Permission struct {
	ID          string
	RealmID     string
	Name        string
	Description string
	Status      PermissionStatus
	Resource    string
	Action      string
	Scope       string
	Constraints map[string]interface{}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
