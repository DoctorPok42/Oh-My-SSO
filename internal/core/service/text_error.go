package service

import (
	"errors"

	"sso.internal/sso/internal/i18n"
)

// textError is a refusal whose sentence can be translated: it wraps a
// sentinel (errors.Is keeps working) and carries the text (Text). Error()
// is the English form.
type textError struct {
	Sentinel error
	Text     i18n.Text
}

func newTextError(sentinel error, t i18n.Text) error { return &textError{Sentinel: sentinel, Text: t} }

func (e *textError) Error() string { return e.Sentinel.Error() + ": " + englishOf(e.Text) }

func (e *textError) Unwrap() error { return e.Sentinel }

// englishOf is a translatable text in English (nil localizer: the code's).
func englishOf(t i18n.Text) string {
	var english *i18n.Localizer
	return english.Text(t)
}

// passwordText is the sentence of a refused password, translatable.
func passwordText(pe *PasswordPolicyError) i18n.Text {
	switch {
	case errors.Is(pe.Err, ErrPasswordTooShort):
		return i18n.M("admin.error.password_too_short", "the password must be at least {min} characters long", "min", pe.MinLength)
	case errors.Is(pe.Err, ErrPasswordTooLong):
		return i18n.M("admin.error.password_too_long", "the password must be at most {max} characters long", "max", pe.MaxLength)
	case errors.Is(pe.Err, ErrPasswordMatchesIdentity):
		return i18n.M("admin.error.password_identity", "the password must not be the username or e-mail")
	}
	return i18n.M("admin.error.password_refused", "this password cannot be used")
}
