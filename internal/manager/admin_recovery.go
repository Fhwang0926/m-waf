package manager

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

var ErrInvalidRecoveryInput = errors.New("username is invalid or password must contain between 12 and 256 characters")

func ResetSystemAdminPassword(ctx context.Context, store *Store, username, password string) error {
	if err := ValidateSystemAdminRecoveryInput(username, password); err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return store.ResetSystemAdminPassword(ctx, username, passwordHash)
}

func ValidateSystemAdminRecoveryInput(username, password string) error {
	username = strings.TrimSpace(username)
	passwordLength := utf8.RuneCountInString(password)
	if !validUsername(username) || !utf8.ValidString(password) || passwordLength < 12 || passwordLength > 256 {
		return ErrInvalidRecoveryInput
	}
	return nil
}
