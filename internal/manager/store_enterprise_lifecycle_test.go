package manager

import (
	"database/sql"
	"testing"
	"time"
)

func TestEnterpriseLifecyclePresentation(t *testing.T) {
	empty := EnterpriseRecord{Status: "ACTIVE"}
	if !empty.Active() || !empty.CanDeletePermanently() || empty.StatusLabel() != "운영 중" {
		t.Fatalf("unexpected empty active enterprise state: %#v", empty)
	}
	used := EnterpriseRecord{Status: "ACTIVE", ServerCount: 1, InstallTokenCount: 2}
	if used.CanDeletePermanently() || used.DependencyCount() != 3 {
		t.Fatalf("used enterprise was considered empty: %#v", used)
	}
	protected := EnterpriseRecord{Status: "ACTIVE", SystemAdminCount: 1, UserCount: 1}
	if !protected.Protected() || protected.CanDeletePermanently() {
		t.Fatalf("system administrator enterprise was not protected: %#v", protected)
	}
	terminated := EnterpriseRecord{Status: "TERMINATED", TerminatedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}
	if terminated.Active() || terminated.StatusLabel() != "운영 종료" {
		t.Fatalf("unexpected terminated enterprise state: %#v", terminated)
	}
}
