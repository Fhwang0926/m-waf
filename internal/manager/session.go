package manager

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName   = "mwaf_session"
	setupCSRFCookieName = "mwaf_setup_csrf"
)

type sessionData struct {
	UserID         string `json:"user_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	Role           Role   `json:"role"`
	EnterpriseID   string `json:"enterprise_id,omitempty"`
	EnterpriseName string `json:"enterprise_name,omitempty"`
	CredentialTag  string `json:"credential_tag"`
	ExpiresAt      int64  `json:"expires_at"`
	CSRF           string `json:"csrf"`
}

func (s sessionData) RoleLabel() string    { return s.Role.Label() }
func (s sessionData) IsSystemAdmin() bool  { return s.Role == RoleSystemAdmin }
func (s sessionData) CanOperate() bool     { return roleAtLeast(s.Role, RoleEnterpriseAdmin) }
func (s sessionData) CanManageUsers() bool { return s.CanOperate() }
func (s sessionData) ScopeEnterpriseID() string {
	if s.IsSystemAdmin() {
		return ""
	}
	return s.EnterpriseID
}

type sessionManager struct {
	key []byte
}

func newSessionManager(key []byte) *sessionManager { return &sessionManager{key: key} }

func (s *sessionManager) setupCSRF() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("setup:" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *sessionManager) validSetupCSRF(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("setup:" + parts[0]))
	actual, err := base64.RawURLEncoding.DecodeString(parts[1])
	return err == nil && hmac.Equal(actual, mac.Sum(nil))
}

func (s *sessionManager) create(user UserRecord) (string, sessionData, error) {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", sessionData{}, err
	}
	data := sessionData{
		UserID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Role: user.Role,
		EnterpriseID: user.EnterpriseID, EnterpriseName: user.EnterpriseName,
		CredentialTag: s.credentialTag(user.PasswordHash), ExpiresAt: time.Now().UTC().Add(8 * time.Hour).Unix(),
		CSRF: base64.RawURLEncoding.EncodeToString(random),
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "", sessionData{}, err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + signature, data, nil
}

func (s *sessionManager) parse(token string) (sessionData, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return sessionData{}, errors.New("invalid session")
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(actual, expected) {
		return sessionData{}, errors.New("invalid session signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return sessionData{}, err
	}
	var data sessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return sessionData{}, err
	}
	if data.UserID == "" || data.Username == "" || data.CSRF == "" || data.CredentialTag == "" || !roleAtLeast(data.Role, RoleEnterpriseUser) || time.Now().UTC().Unix() >= data.ExpiresAt {
		return sessionData{}, errors.New("expired session")
	}
	return data, nil
}

func (s *sessionManager) credentialTag(passwordHash string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("credential:" + passwordHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func setSetupCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: setupCSRFCookieName, Value: token, Path: "/setup", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func clearSetupCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: setupCSRFCookieName, Value: "", Path: "/setup", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func secureEqual(a, b []byte) bool {
	ah := sha256.Sum256(a)
	bh := sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

type requestLimitWindow struct {
	started time.Time
	count   int
}

type requestLimiter struct {
	mu      sync.Mutex
	windows map[string]requestLimitWindow
	limit   int
	window  time.Duration
}

func newRequestLimiter(limit int, window time.Duration) *requestLimiter {
	return &requestLimiter{windows: make(map[string]requestLimitWindow), limit: limit, window: window}
}

func (l *requestLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.windows) > 1024 {
		for entryKey, entry := range l.windows {
			if now.Sub(entry.started) >= l.window {
				delete(l.windows, entryKey)
			}
		}
	}
	current := l.windows[key]
	if current.started.IsZero() || now.Sub(current.started) >= l.window {
		l.windows[key] = requestLimitWindow{started: now, count: 1}
		return true
	}
	if current.count >= l.limit {
		return false
	}
	current.count++
	l.windows[key] = current
	return true
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{attempts: make(map[string][]time.Time)} }

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	old := l.attempts[key]
	current := old[:0]
	for _, attempt := range old {
		if attempt.After(cutoff) {
			current = append(current, attempt)
		}
	}
	l.attempts[key] = current
	return len(current) < 5
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	l.attempts[key] = append(l.attempts[key], time.Now())
	l.mu.Unlock()
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
