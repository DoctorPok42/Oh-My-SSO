package repository

import "errors"

var ErrNotFound = errors.New("repository: not found")
var ErrReservedRealmName = errors.New("repository: reserved realm name")

// ErrConflict: a uniqueness constraint refused the write (e.g. a WebAuthn
// credential id that is already registered).
var ErrConflict = errors.New("repository: conflict with an existing record")
