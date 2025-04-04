package auth

import "errors"

var (
	ErrInvalidCreditionals = errors.New("invalid creditionals")
	ErrInvalidUserID       = errors.New("invalid user id")
	ErrInvalidAppID        = errors.New("invalid app id")
	ErrUserExists          = errors.New("user already exists")
)
