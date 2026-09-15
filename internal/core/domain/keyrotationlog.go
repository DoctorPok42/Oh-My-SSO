package domain

import "time"

type KeyRotationAction string

const (
	KeyRotationCreated     KeyRotationAction = "created"
	KeyRotationRotated     KeyRotationAction = "rotated"
	KeyRotationRetired     KeyRotationAction = "retired"
	KeyRotationCompromised KeyRotationAction = "compromised"
	KeyRotationDeleted     KeyRotationAction = "deleted"
)

type KeyRotationLog struct {
	ID           string
	SigningKeyID string
	Action       KeyRotationAction
	TriggeredBy  string
	Reason       string
	CreatedAt    time.Time
}
