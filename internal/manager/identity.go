package manager

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Role string

const (
	RoleEnterpriseUser  Role = "enterprise_user"
	RoleEnterpriseAdmin Role = "enterprise_admin"
	RoleSystemAdmin     Role = "system_admin"

	passwordIterations = 600_000
)

var ErrSetupComplete = errors.New("system administrator is already configured")

func (r Role) Label() string {
	switch r {
	case RoleSystemAdmin:
		return "시스템 관리자"
	case RoleEnterpriseAdmin:
		return "기업 관리자"
	default:
		return "기업 사용자"
	}
}

func roleAtLeast(actual, required Role) bool {
	levels := map[Role]int{
		RoleEnterpriseUser:  1,
		RoleEnterpriseAdmin: 2,
		RoleSystemAdmin:     3,
	}
	return levels[actual] >= levels[required]
}

func validEnterpriseRole(role Role) bool {
	return role == RoleEnterpriseUser || role == RoleEnterpriseAdmin
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(derived)), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100_000 || iterations > 2_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expected) != 32 {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	return err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 128 {
		return false
	}
	for _, char := range username {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
