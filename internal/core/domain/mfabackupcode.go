package domain

import "time"

type MfaBackupCode struct {
	ID        string
	UserID    string
	BatchID   string
	CodeHash  string
	Used      bool
	UsedAt    time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}
