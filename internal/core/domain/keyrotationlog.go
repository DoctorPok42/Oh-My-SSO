package domain

import "time"

type KeyRotationAction string

const (
	KeyRotationCreated     KeyRotationAction = "created"
	KeyRotationRotated     KeyRotationAction = "rotated"
	KeyRotationRetired     KeyRotationAction = "retired"
	KeyRotationCompromised KeyRotationAction = "compromised"
	KeyRotationDeleted     KeyRotationAction = "deleted"
	// KeyRotationActivated (Step 11): a "pending" key started to sign.
	KeyRotationActivated KeyRotationAction = "activated"
)

type KeyRotationLog struct {
	ID           string
	SigningKeyID string
	Action       KeyRotationAction
	TriggeredBy  string
	Reason       string
	CreatedAt    time.Time
}
