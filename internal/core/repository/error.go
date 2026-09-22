package repository

import "errors"

var ErrNotFound = errors.New("repository: not found")
var ErrReservedRealmName = errors.New("repository: reserved realm name")
