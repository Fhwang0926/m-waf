package manager

import (
	"errors"
	"testing"
)

func TestResetSystemAdminPasswordRejectsInvalidInputBeforeStoreUse(t *testing.T) {
	for _, test := range []struct {
		name     string
		username string
		password string
	}{
		{name: "invalid username", username: "x", password: "valid-password"},
		{name: "short password", username: "admin", password: "too-short"},
		{name: "long password", username: "admin", password: string(make([]byte, 257))},
		{name: "invalid utf8", username: "admin", password: "valid-password-" + string([]byte{0xff})},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSystemAdminRecoveryInput(test.username, test.password)
			if !errors.Is(err, ErrInvalidRecoveryInput) {
				t.Fatalf("expected invalid recovery password error, got %v", err)
			}
		})
	}
}
