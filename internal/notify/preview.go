package notify

import (
	"time"

	"sso.internal/sso/internal/core/domain"
	"sso.internal/sso/internal/i18n"
)

// PreviewData returns realistic sample data for an e-mail: what the
// dispatcher would fill for a user "alice" of a realm "Acme". `idp mail test
// --all` sends every template with it (to look at them, and at their score,
// in Mailpit), and the tests render with it.
func PreviewData(tmpl Template, product string, now time.Time) Data {
	return PreviewDataIn(nil, tmpl, product, now)
}

// PreviewDataIn is PreviewData in a language (nil: English).
func PreviewDataIn(loc *i18n.Localizer, tmpl Template, product string, now time.Time) Data {
	const base = "https://sso.example.com/r/acme"
	d := Data{
		Lang:              loc.Lang(),
		Product:           product,
		Realm:             "Acme",
		Username:          "alice",
		When:              formatTime(loc, now),
		IPAddress:         "203.0.113.42",
		Device:            describeUserAgent(loc, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"),
		Location:          "France",
		ForgotPasswordURL: base + "/auth/forgot-password",
	}
	resetURL := base + "/auth/reset-password#token=Xk3pQ9vRt2LmN8wYz4AbCdEfGh7JkLmNoPqRsTuVwXy"
	switch tmpl {
	case TemplatePasswordReset, TemplatePasswordResetRequired:
		d.ResetURL, d.ExpiresIn = resetURL, humanDuration(loc, 30*time.Minute)
	case TemplateAccountInvite:
		d.ResetURL, d.ExpiresIn = resetURL, humanDuration(loc, 72*time.Hour)
	case TemplateMfaMethodAdded, TemplateMfaMethodRemoved:
		d.MethodLabel, d.MethodName = methodLabel(loc, domain.MfaMethodPasskey), "MacBook Touch ID"
	case TemplateAccountLocked:
		d.FailedAttempts = 5
		d.LockDuration = humanDuration(loc, 15 * time.Minute)
		d.LockedUntil = formatTime(loc, now.Add(15 * time.Minute))
	case TemplateSuspiciousLogin:
		d.Reasons = []string{
			reasonText(loc, domain.SuspiciousNewCountry, d.Location, ""),
			reasonText(loc, domain.SuspiciousUnusualHour, d.Location, ""),
		}
	case TemplateAppConnected:
		d.AppName = "Grafana"
		d.AppAccess = []string{knownText(loc, accessTexts, "Your e-mail address"), "Your groups"}
	case TemplateAdminRecovery:
		d.RecoveryKind = knownText(loc, recoveryKinds, "a new administrator account")
		d.RecoveryActor = "root@admin-host"
		d.RecoveryAccount = "rescue-admin"
	case TemplateUserImportFinished:
		d.ImportRealm, d.ImportFile = "acme", "new-hires.csv"
		d.ImportTotal, d.ImportCreated, d.ImportFailed = 240, 238, 2
		d.ImportURL = "https://admin.example.com/r/acme/users?import=8f14e45f"
	case TemplateTest:
		d.Realm, d.Username, d.IPAddress, d.Device, d.Location, d.ForgotPasswordURL = "", "", "", "", "", ""
	}
	return d
}
