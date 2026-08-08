package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

type PolicySettings struct {
	SchemaVersion          int               `json:"schema_version,omitempty"`
	TemplateKey            string            `json:"template_key,omitempty"`
	TemplateVersion        string            `json:"template_version,omitempty"`
	CRSTrack               string            `json:"crs_track,omitempty"`
	CRSVersion             string            `json:"crs_version,omitempty"`
	Target                 string            `json:"target,omitempty"`
	AutoUpdate             bool              `json:"auto_update,omitempty"`
	PolicyOrigin           string            `json:"policy_origin,omitempty"`
	MigrationStatus        string            `json:"migration_status,omitempty"`
	MigratedFrom           string            `json:"migrated_from,omitempty"`
	ArtifactFormat         string            `json:"artifact_format,omitempty"`
	ParanoiaLevel          int               `json:"paranoia_level"`
	ExecutingParanoiaLevel int               `json:"executing_paranoia_level,omitempty"`
	InboundScore           int               `json:"inbound_anomaly_score"`
	OutboundScore          int               `json:"outbound_anomaly_score,omitempty"`
	RequestBody            bool              `json:"request_body_access"`
	ResponseBody           bool              `json:"response_body_access,omitempty"`
	EarlyBlocking          bool              `json:"early_blocking,omitempty"`
	SamplingPercentage     int               `json:"sampling_percentage,omitempty"`
	LegacyPolicyConfirmed  bool              `json:"legacy_policy_confirmed,omitempty"`
	ExcludedPaths          []string          `json:"excluded_paths,omitempty"`
	ExcludedIPs            []string          `json:"excluded_ips,omitempty"`
	Exclusions             []PolicyExclusion `json:"exclusions,omitempty"`
	CustomRules            string            `json:"custom_rules,omitempty"`
	CustomRuleCount        int               `json:"custom_rule_count"`
}

type ManagedPolicyMetadata struct {
	SchemaVersion   int
	TemplateKey     string
	TemplateVersion string
	CRSTrack        string
	CRSVersion      string
	Target          string
	AutoUpdate      bool
	PolicyOrigin    string
	MigrationStatus string
	MigratedFrom    string
}

var (
	customRuleID        = regexp.MustCompile(`(?i)\bid\s*:\s*['"]?([0-9]+)`)
	forbiddenRuleToken  = regexp.MustCompile(`(?i)\b(exec|proxy|prepend|append|redirect)\s*:`)
	forbiddenRuleAction = regexp.MustCompile(`(?i)(^|,|\s)(drop|allow)(,|\s|$)|ctl\s*:\s*ruleEngine\s*=\s*Off`)
)

func buildPolicyArtifact(mode string, paranoiaLevel, inboundScore int, requestBody bool, pathsText, ipsText, customRules string) ([]byte, string, error) {
	return buildManagedPolicyArtifact(mode, paranoiaLevel, inboundScore, requestBody, pathsText, ipsText, customRules, ManagedPolicyMetadata{})
}

func buildManagedPolicyArtifact(mode string, paranoiaLevel, inboundScore int, requestBody bool, pathsText, ipsText, customRules string, metadata ManagedPolicyMetadata) ([]byte, string, error) {
	if mode != "DetectionOnly" && mode != "On" {
		return nil, "", errors.New("invalid WAF mode")
	}
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		return nil, "", errors.New("paranoia level must be 1..4")
	}
	if inboundScore < 1 || inboundScore > 100 {
		return nil, "", errors.New("inbound anomaly score must be 1..100")
	}
	paths, err := policyPaths(pathsText)
	if err != nil {
		return nil, "", err
	}
	ips, err := policyIPs(ipsText)
	if err != nil {
		return nil, "", err
	}
	rules, ruleCount, err := safeCustomRules(customRules)
	if err != nil {
		return nil, "", err
	}
	settings := PolicySettings{
		SchemaVersion: metadata.SchemaVersion, TemplateKey: metadata.TemplateKey, TemplateVersion: metadata.TemplateVersion,
		CRSTrack: metadata.CRSTrack, CRSVersion: metadata.CRSVersion, Target: metadata.Target, AutoUpdate: metadata.AutoUpdate,
		PolicyOrigin: metadata.PolicyOrigin, MigrationStatus: metadata.MigrationStatus, MigratedFrom: metadata.MigratedFrom,
		ParanoiaLevel: paranoiaLevel, InboundScore: inboundScore, RequestBody: requestBody,
		ExcludedPaths: paths, ExcludedIPs: ips, CustomRules: rules, CustomRuleCount: ruleCount,
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return nil, "", err
	}
	requestBodyMode := "Off"
	if requestBody {
		requestBodyMode = "On"
	}
	var artifact strings.Builder
	fmt.Fprintf(&artifact, "# Generated and signed by M-WAF Manager.\nSecRuleEngine %s\nSecRequestBodyAccess %s\n", mode, requestBodyMode)
	fmt.Fprintf(&artifact, "SecAction \"id:210000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n", paranoiaLevel, paranoiaLevel)
	fmt.Fprintf(&artifact, "SecAction \"id:210001,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", inboundScore)
	for i, ip := range ips {
		fmt.Fprintf(&artifact, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", ip, 220000+i)
	}
	for i, path := range paths {
		fmt.Fprintf(&artifact, "SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", path, 230000+i)
	}
	if rules != "" {
		artifact.WriteString("# Custom rules\n")
		artifact.WriteString(rules)
		artifact.WriteByte('\n')
	}
	if artifact.Len() > 1<<20 {
		return nil, "", errors.New("generated policy exceeds 1 MiB")
	}
	return []byte(artifact.String()), string(settingsJSON), nil
}

func buildEnterprisePolicyArtifact(policyTemplate systempolicy.Template, mode string, paranoiaLevel, inboundScore int, requestBody bool, pathsText, ipsText, customRules string, metadata ManagedPolicyMetadata) ([]byte, string, error) {
	enterprisePaths, err := policyPaths(pathsText)
	if err != nil {
		return nil, "", err
	}
	enterpriseIPs, err := policyIPs(ipsText)
	if err != nil {
		return nil, "", err
	}
	enterpriseRules, enterpriseRuleCount, err := safeCustomRules(customRules)
	if err != nil {
		return nil, "", err
	}
	if err := validateCustomRuleScopeIDs(enterpriseRules, PolicyScopeEnterprise); err != nil {
		return nil, "", err
	}
	effectivePaths := append(append([]string(nil), policyTemplate.Defaults.ExcludedPaths...), enterprisePaths...)
	effectiveIPs := append(append([]string(nil), policyTemplate.Defaults.ExcludedIPs...), enterpriseIPs...)
	effectiveRules := strings.Join(uniqueNonEmptyLines(policyTemplate.Defaults.CustomRules+"\n"+enterpriseRules), "\n")
	artifact, _, err := buildManagedPolicyArtifact(mode, paranoiaLevel, inboundScore, requestBody, strings.Join(effectivePaths, "\n"), strings.Join(effectiveIPs, "\n"), effectiveRules, metadata)
	if err != nil {
		return nil, "", err
	}
	settings := PolicySettings{
		SchemaVersion: metadata.SchemaVersion, TemplateKey: metadata.TemplateKey, TemplateVersion: metadata.TemplateVersion,
		CRSTrack: metadata.CRSTrack, CRSVersion: metadata.CRSVersion, Target: metadata.Target, AutoUpdate: metadata.AutoUpdate,
		PolicyOrigin: metadata.PolicyOrigin, MigrationStatus: metadata.MigrationStatus, MigratedFrom: metadata.MigratedFrom,
		ParanoiaLevel: paranoiaLevel, InboundScore: inboundScore, RequestBody: requestBody,
		ExcludedPaths: enterprisePaths, ExcludedIPs: enterpriseIPs, CustomRules: enterpriseRules, CustomRuleCount: enterpriseRuleCount,
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return nil, "", err
	}
	return artifact, string(settingsJSON), nil
}

func policyPaths(text string) ([]string, error) {
	values := uniqueNonEmptyLines(text)
	if len(values) > 100 {
		return nil, errors.New("excluded paths are limited to 100")
	}
	for _, value := range values {
		if len(value) > 512 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\"\\\r\n") {
			return nil, fmt.Errorf("invalid excluded path %q", value)
		}
	}
	return values, nil
}

func policyIPs(text string) ([]string, error) {
	values := uniqueNonEmptyLines(text)
	if len(values) > 100 {
		return nil, errors.New("excluded IPs are limited to 100")
	}
	for _, value := range values {
		if net.ParseIP(value) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return nil, fmt.Errorf("invalid excluded IP or CIDR %q", value)
		}
	}
	return values, nil
}

func safeCustomRules(text string) (string, int, error) {
	text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	if len(text) > 32<<10 {
		return "", 0, errors.New("custom rules exceed 32 KiB")
	}
	if text == "" {
		return "", 0, nil
	}
	seen := make(map[int]bool)
	count := 0
	for number, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(line, "SecRule ") || strings.HasSuffix(line, "\\") {
			return "", 0, fmt.Errorf("custom rule line %d must be one complete SecRule directive", number+1)
		}
		if forbiddenRuleToken.MatchString(line) || strings.Contains(lower, "@inspectfile") {
			return "", 0, fmt.Errorf("custom rule line %d contains forbidden action or operator", number+1)
		}
		if !validSecRuleQuotes(line) {
			return "", 0, fmt.Errorf("custom rule line %d has invalid quotes or action syntax", number+1)
		}
		actions := secRuleActions(line)
		if actions == "" || !strings.Contains(strings.ToLower(actions), "phase:") || forbiddenRuleAction.MatchString(actions) {
			return "", 0, fmt.Errorf("custom rule line %d has missing or forbidden actions", number+1)
		}
		match := customRuleID.FindStringSubmatch(line)
		if len(match) != 2 {
			return "", 0, fmt.Errorf("custom rule line %d requires an id", number+1)
		}
		id, _ := strconv.Atoi(match[1])
		validNew := id >= systemRuleIDMin && id <= systemRuleIDMax || id >= enterpriseRuleIDMin && id <= enterpriseRuleIDMax
		if (!validNew && !isLegacyPolicyRuleID(id)) || seen[id] {
			return "", 0, fmt.Errorf("custom rule line %d requires a unique enterprise or system rule id", number+1)
		}
		seen[id] = true
		count++
	}
	return text, count, nil
}

func validateCustomRuleIDRange(rules string, minimum, maximum int) error {
	for _, match := range customRuleID.FindAllStringSubmatch(rules, -1) {
		id, _ := strconv.Atoi(match[1])
		if id < minimum || id > maximum {
			return fmt.Errorf("custom rules require ids in %d..%d", minimum, maximum)
		}
	}
	return nil
}

func validateCustomRuleScopeIDs(rules, scope string) error {
	for _, match := range customRuleID.FindAllStringSubmatch(rules, -1) {
		id, _ := strconv.Atoi(match[1])
		valid := scope == PolicyScopeSystem && id >= systemRuleIDMin && id <= systemRuleIDMax ||
			scope == PolicyScopeEnterprise && id >= enterpriseRuleIDMin && id <= enterpriseRuleIDMax
		if !valid {
			return fmt.Errorf("custom Rule ID %d is outside the %s namespace", id, scope)
		}
	}
	return nil
}

func validSecRuleQuotes(line string) bool {
	quotes := 0
	escaped := false
	for _, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			quotes++
		}
	}
	return !escaped && quotes == 4
}

func secRuleActions(line string) string {
	end := strings.LastIndex(line, `"`)
	if end <= 0 {
		return ""
	}
	start := strings.LastIndex(line[:end], `"`)
	if start < 0 || start+1 >= end {
		return ""
	}
	return strings.TrimSpace(line[start+1 : end])
}

func uniqueNonEmptyLines(text string) []string {
	seen := make(map[string]bool)
	values := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		value := strings.TrimSpace(raw)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	return values
}
