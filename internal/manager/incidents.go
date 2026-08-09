package manager

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const (
	AttackCategoryHTTPProtocol = "HTTP_PROTOCOL"
	AttackCategoryInjection    = "INJECTION"
	AttackCategoryXSS          = "XSS"
	AttackCategoryFilePath     = "FILE_PATH"
	AttackCategoryScannerBot   = "SCANNER_BOT"
	AttackCategoryOther        = "OTHER"
)

type IncidentRecord struct {
	ID              uint64        `json:"id"`
	EnterpriseID    string        `json:"enterprise_id,omitempty"`
	EnterpriseName  string        `json:"enterprise_name"`
	AgentID         string        `json:"server_id"`
	ServerName      string        `json:"server_name"`
	IncidentKey     string        `json:"incident_key"`
	OccurredAt      time.Time     `json:"occurred_at"`
	Category        string        `json:"category"`
	ClientIP        string        `json:"client_ip,omitempty"`
	CountryCode     string        `json:"country_code"`
	Method          string        `json:"method"`
	URI             string        `json:"uri"`
	StatusCode      uint16        `json:"status_code"`
	Blocked         bool          `json:"blocked"`
	PrimaryEventID  uint64        `json:"primary_event_id,omitempty"`
	PolicyRevision  string        `json:"policy_revision,omitempty"`
	PolicyID        string        `json:"policy_id,omitempty"`
	MatchedVariable string        `json:"matched_variable,omitempty"`
	PrimaryRuleID   string        `json:"primary_rule_id,omitempty"`
	PrimaryMessage  string        `json:"primary_message,omitempty"`
	Events          []EventRecord `json:"events,omitempty"`
}

func (i IncidentRecord) CategoryLabel() string { return attackCategoryLabel(i.Category) }
func (i IncidentRecord) CountryLabel() string  { return countryCodeLabel(i.CountryCode) }

func attackCategoryLabel(category string) string {
	switch category {
	case AttackCategoryHTTPProtocol:
		return "HTTP·프로토콜"
	case AttackCategoryInjection:
		return "인젝션"
	case AttackCategoryXSS:
		return "XSS"
	case AttackCategoryFilePath:
		return "파일·경로 공격"
	case AttackCategoryScannerBot:
		return "스캐너·자동화"
	default:
		return "기타"
	}
}

func attackCategoryClass(category string) string {
	switch category {
	case AttackCategoryXSS, AttackCategoryInjection, AttackCategoryFilePath:
		return "danger"
	case AttackCategoryScannerBot, AttackCategoryHTTPProtocol:
		return "warn"
	default:
		return "info"
	}
}

func countryCodeLabel(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "--":
		return "내부 네트워크"
	case "", "ZZ":
		return "알 수 없음"
	default:
		return strings.ToUpper(code)
	}
}

func incidentKey(event model.SecurityEvent) string {
	if value := strings.TrimSpace(event.RequestID); value != "" {
		return truncate(value, 128)
	}
	if value := strings.TrimSpace(event.TransactionID); value != "" {
		return truncate(value, 128)
	}
	return truncate(event.EventID, 128)
}

func isSummaryRule(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	return strings.HasPrefix(ruleID, "949") || strings.HasPrefix(ruleID, "959") || strings.HasPrefix(ruleID, "980")
}

func classifySecurityEvent(event model.SecurityEvent) string {
	joined := strings.ToLower(strings.Join(event.RuleTags, " ") + " " + event.Message)
	switch {
	case strings.Contains(joined, "attack-xss") || strings.Contains(joined, "cross-site scripting"):
		return AttackCategoryXSS
	case containsAny(joined, "attack-sqli", "attack-injection", "attack-rce", "command-injection", "sql injection", "remote code execution"):
		return AttackCategoryInjection
	case containsAny(joined, "attack-lfi", "attack-rfi", "path-traversal", "file-upload", "file inclusion", "directory traversal"):
		return AttackCategoryFilePath
	case containsAny(joined, "scanner", "automation", "bot", "reputation", "user-agent"):
		return AttackCategoryScannerBot
	case containsAny(joined, "protocol", "method-enforcement", "protocol-enforcement", "http-policy", "encoding"):
		return AttackCategoryHTTPProtocol
	default:
		return AttackCategoryOther
	}
}

func (s *Server) enrichEventRuleTags(ctx context.Context, events []model.SecurityEvent) {
	type revisionRuleTags struct {
		loaded bool
		tags   map[int][]string
	}
	cache := make(map[string]revisionRuleTags)
	for index := range events {
		event := &events[index]
		if len(event.RuleTags) != 0 || event.PolicyRevision == "" || isSummaryRule(event.RuleID) {
			continue
		}
		ruleID, err := strconv.Atoi(strings.TrimSpace(event.RuleID))
		if err != nil || ruleID <= 0 {
			continue
		}
		entry, exists := cache[event.PolicyRevision]
		if !exists {
			entry.loaded = true
			configuration, loadErr := s.store.PolicyConfigurationByRevisionID(ctx, event.PolicyRevision)
			if loadErr == nil && configuration.CRSReleaseID != "" {
				_, sourceIndex, found, indexErr := s.indexedPolicySource(ctx, configuration.CRSReleaseID)
				if indexErr == nil && found {
					entry.tags = make(map[int][]string, len(sourceIndex.Rules))
					for _, rule := range sourceIndex.Rules {
						entry.tags[rule.ID] = append([]string(nil), rule.Tags...)
					}
				}
			}
			cache[event.PolicyRevision] = entry
		}
		if entry.loaded && entry.tags != nil {
			event.RuleTags = normalizeEventRuleTags(entry.tags[ruleID])
		}
	}
}

func normalizeEventRuleTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	result := make([]string, 0, min(len(tags), 32))
	for _, tag := range tags {
		tag = truncate(strings.TrimSpace(tag), 255)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		result = append(result, tag)
		if len(result) == 32 {
			break
		}
	}
	return result
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func selectPrimaryEvent(events []model.SecurityEvent) model.SecurityEvent {
	if len(events) == 0 {
		return model.SecurityEvent{}
	}
	candidates := append([]model.SecurityEvent(nil), events...)
	sort.SliceStable(candidates, func(i, j int) bool {
		leftSummary, rightSummary := isSummaryRule(candidates[i].RuleID), isSummaryRule(candidates[j].RuleID)
		if leftSummary != rightSummary {
			return !leftSummary
		}
		leftOther := classifySecurityEvent(candidates[i]) == AttackCategoryOther
		rightOther := classifySecurityEvent(candidates[j]) == AttackCategoryOther
		return !leftOther && rightOther
	})
	return candidates[0]
}

func canonicalEventIP(value string) (string, []byte) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return "", nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), append([]byte(nil), v4...)
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", nil
	}
	return v6.String(), append([]byte(nil), v6...)
}

func displayStoredIP(raw []byte) string {
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return ""
	}
	return net.IP(raw).String()
}
