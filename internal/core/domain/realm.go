package domain

import "time"

type RealmStatus string

const (
	RealmActive   RealmStatus = "active"
	RealmInactive RealmStatus = "inactive"
)

type Realm struct {
	ID            string
	Name          string
	IsSystemRealm bool
	DisplayName   string
	Status        RealmStatus
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
