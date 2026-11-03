package notify

import (
	"time"

	"sso.internal/sso/internal/core/domain"
)

// PreviewData returns realistic sample data for an e-mail: what the
// dispatcher would fill for a user "alice" of a realm "Acme". `idp mail test
// --all` sends every template with it (to look at them, and at their score,
// in Mailpit), and the tests render with it.
func PreviewData(tmpl Template, product string, now time.Time) Data {
	const base = "https://sso.example.com/r/acme"
	d := Data{
		Product:           product,
		Realm:             "Acme",
		Username:          "alice",
		When:              formatTime(now),
		IPAddress:         "203.0.113.42",
		Device:            "Firefox on Windows",
		Location:          "France",
		ForgotPasswordURL: base + "/auth/forgot-password",
	}
	resetURL := base + "/auth/reset-password#token=Xk3pQ9vRt2LmN8wYz4AbCdEfGh7JkLmNoPqRsTuVwXy"
	switch tmpl {
	case TemplatePasswordReset:
		d.ResetURL, d.ExpiresIn = resetURL, humanDuration(30*time.Minute)
	case TemplateAccountInvite:
		d.ResetURL, d.ExpiresIn = resetURL, humanDuration(72*time.Hour)
	case TemplateMfaMethodAdded, TemplateMfaMethodRemoved:
		d.MethodLabel, d.MethodName = methodLabel(domain.MfaMethodPasskey), "MacBook Touch ID"
	case TemplateAccountLocked:
		d.FailedAttempts = 5
		d.LockDuration = humanDuration(15 * time.Minute)
		d.LockedUntil = formatTime(now.Add(15 * time.Minute))
	case TemplateSuspiciousLogin:
		d.Reasons = []string{
			reasonText(domain.SuspiciousNewCountry, d.Location, ""),
			reasonText(domain.SuspiciousUnusualHour, d.Location, ""),
		}
	case TemplateAppConnected:
		d.AppName = "Grafana"
		d.AppAccess = []string{"your e-mail address", "your groups"}
	case TemplateAdminRecovery:
		d.RecoveryKind = "a new administrator account"
		d.RecoveryActor = "root@admin-host"
		d.RecoveryAccount = "rescue-admin"
	case TemplateTest:
		d.Realm, d.Username, d.IPAddress, d.Device, d.Location, d.ForgotPasswordURL = "", "", "", "", "", ""
	}
	return d
}
