package domain

import "time"

// TrustedDevice: a device where the user ticked "Don't ask again on this
// alone signs them in there when no policy requires MFA.
type TrustedDevice struct {
	ID         string
	RealmID    string
	UserID     string
	DeviceHash string // SHA-256 of the sso_device cookie
	IPAddress  string // of the last sign-in that used it (first: where the box was ticked)
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time // zero: not used yet
}

// Active tells whether the trust still holds at now.
func (d *TrustedDevice) Active(now time.Time) bool { return now.Before(d.ExpiresAt) }
