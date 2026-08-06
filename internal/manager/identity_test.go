package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRoleBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		actual   Role
		required Role
		allowed  bool
	}{
		{"enterprise user can read", RoleEnterpriseUser, RoleEnterpriseUser, true},
		{"enterprise user cannot operate", RoleEnterpriseUser, RoleEnterpriseAdmin, false},
		{"enterprise admin can operate", RoleEnterpriseAdmin, RoleEnterpriseAdmin, true},
		{"enterprise admin cannot manage system", RoleEnterpriseAdmin, RoleSystemAdmin, false},
		{"system admin can manage enterprise", RoleSystemAdmin, RoleEnterpriseAdmin, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := roleAtLeast(test.actual, test.required); got != test.allowed {
				t.Fatalf("roleAtLeast(%q, %q) = %v", test.actual, test.required, got)
			}
		})
	}
}

func TestEnterpriseScope(t *testing.T) {
	enterprise := sessionData{Role: RoleEnterpriseAdmin, EnterpriseID: "enterprise-a"}
	if got := enterprise.ScopeEnterpriseID(); got != "enterprise-a" {
		t.Fatalf("enterprise scope = %q", got)
	}
	system := sessionData{Role: RoleSystemAdmin, EnterpriseID: "unexpected"}
	if got := system.ScopeEnterpriseID(); got != "" {
		t.Fatalf("system scope = %q", got)
	}
}

func TestRequireRoleRejectsEnterpriseUser(t *testing.T) {
	server := &Server{}
	called := false
	handler := server.requireRole(RoleEnterpriseAdmin, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodGet, "/policies/new", nil)
	request = request.WithContext(context.WithValue(request.Context(), contextSession, sessionData{Role: RoleEnterpriseUser, EnterpriseID: "enterprise-a"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v", response.Code, called)
	}
}

func TestRequestLimiter(t *testing.T) {
	limiter := newRequestLimiter(2, time.Minute)
	if !limiter.allow("client") || !limiter.allow("client") || limiter.allow("client") {
		t.Fatal("request limiter did not enforce its fixed window")
	}
	if !limiter.allow("other-client") {
		t.Fatal("request limiter mixed independent clients")
	}
}
