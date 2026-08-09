package manager

import (
	"testing"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestIncidentPrimaryEventExcludesEvaluationRules(t *testing.T) {
	events := []model.SecurityEvent{
		{RuleID: "949110", Message: "Inbound Anomaly Score Exceeded", RuleTags: []string{"evaluation"}},
		{RuleID: "942100", Message: "SQL injection detected", RuleTags: []string{"attack-sqli"}},
		{RuleID: "980130", Message: "Inbound Anomaly Score"},
	}
	primary := selectPrimaryEvent(events)
	if primary.RuleID != "942100" || classifySecurityEvent(primary) != AttackCategoryInjection {
		t.Fatalf("unexpected incident primary event: %#v", primary)
	}
}

func TestIncidentKeyUsesRequestThenTransactionThenEvent(t *testing.T) {
	if got := incidentKey(model.SecurityEvent{RequestID: "request", TransactionID: "transaction", EventID: "event"}); got != "request" {
		t.Fatalf("request ID must be authoritative, got %q", got)
	}
	if got := incidentKey(model.SecurityEvent{TransactionID: "transaction", EventID: "event"}); got != "transaction" {
		t.Fatalf("transaction ID must be the compatibility fallback, got %q", got)
	}
	if got := incidentKey(model.SecurityEvent{EventID: "event"}); got != "event" {
		t.Fatalf("event ID must be the final fallback, got %q", got)
	}
}
