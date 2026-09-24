package entstore

import (
	"sso.internal/sso/ent"
	"sso.internal/sso/internal/core/repository"
)

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func mapNotFound(err error) error {
	if err != nil && ent.IsNotFound(err) {
		return repository.ErrNotFound
	}
	return err
}
