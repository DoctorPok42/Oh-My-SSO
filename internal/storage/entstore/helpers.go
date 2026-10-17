package entstore

import (
	"time"

	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/repository"
)

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonZeroTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func mapNotFound(err error) error {
	if err != nil && ent.IsNotFound(err) {
		return repository.ErrNotFound
	}
	return err
}
