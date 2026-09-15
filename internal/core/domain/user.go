package domain

import "time"

type UserStatus string

const (
	UserActive    UserStatus = "active"
	UserInactive  UserStatus = "inactive"
	UserSuspended UserStatus = "suspended"
)

type User struct {
	ID					 string
	RealmID				 string
	Username			 string
	PasswordHash		 string
	Email				 string
	CreatedAt			 time.Time
	UpdatedAt			 time.Time
	DeletedAt			 *time.Time
	Status				 UserStatus
	LastLoginAt		 *time.Time
	Profile				 map[string]interface{}
}
