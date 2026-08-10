package migrations

import (
	"strings"
	"testing"
)

func TestProtectionPolicyMembershipMigrationPreservesEffectiveTargets(t *testing.T) {
	raw, err := files.ReadFile("014_protection_policy_membership.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS enterprise_policy_servers",
		"server_id CHAR(36) PRIMARY KEY",
		"source_revision_id CHAR(36)",
		"SET t.source_revision_id=COALESCE(r.from_revision_id,ds.policy_revision_id)",
		"ep.status='ACTIVE'",
		"WHEN ep.target=CONCAT('server:',s.id) THEN 3",
		"WHEN ep.target LIKE 'group:%' THEN 2",
		"ELSE 1",
		"sg.enterprise_id=ep.enterprise_id",
		"ON DUPLICATE KEY UPDATE enterprise_policy_id=VALUES(enterprise_policy_id)",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("membership migration is missing %q", expected)
		}
	}
	upper := strings.ToUpper(script)
	if strings.Contains(upper, "DELETE FROM SERVER_GROUPS") || strings.Contains(upper, "DROP TABLE SERVER_GROUPS") {
		t.Fatalf("membership migration must preserve legacy server group data")
	}
}
