package errkind

import (
	"errors"
)

var (
	ErrInvalidArgument = errors.New("invalid argument")
	ErrNotFound        = errors.New("not found")
	ErrInvalidRequest  = errors.New("invalid request")
	ErrInvalidAPIKey   = errors.New("invalid api key")
	ErrInvalidUser     = errors.New("invalid user")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
	ErrEmptyValue      = errors.New("empty value")
	ErrExternalService = errors.New("external service")
	ErrInternal        = errors.New("internal")
	ErrUnknown         = errors.New("unknown")
	ErrNotImplemented  = errors.New("not implemented")
	ErrConflict        = errors.New("conflict")
)
