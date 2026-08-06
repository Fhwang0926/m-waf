package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type PolicySettings struct {
	ParanoiaLevel   int      `json:"paranoia_level"`
	InboundScore    int      `json:"inbound_anomaly_score"`
	RequestBody     bool     `json:"request_body_access"`
	ExcludedPaths   []string `json:"excluded_paths,omitempty"`
	ExcludedIPs     []string `json:"excluded_ips,omitempty"`
	CustomRuleCount int      `json:"custom_rule_count"`
}

var (
	customRuleID       = regexp.MustCompile(`(?i)\bid\s*:\s*['"]?([0-9]+)`)
	forbiddenRuleToken = regexp.MustCompile(`(?i)\b(exec|proxy|prepend|append)\s*:`)
)

func buildPolicyArtifact(mode string, paranoiaLevel, inboundScore int, requestBody bool, pathsText, ipsText, customRules string) ([]byte, string, error) {
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
	settings := PolicySettings{ParanoiaLevel: paranoiaLevel, InboundScore: inboundScore, RequestBody: requestBody, ExcludedPaths: paths, ExcludedIPs: ips, CustomRuleCount: ruleCount}
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
	fmt.Fprintf(&artifact, "SecAction \"id:210000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d\"\n", paranoiaLevel)
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
		match := customRuleID.FindStringSubmatch(line)
		if len(match) != 2 {
			return "", 0, fmt.Errorf("custom rule line %d requires an id", number+1)
		}
		id, _ := strconv.Atoi(match[1])
		if id < 100000 || id > 199999 || seen[id] {
			return "", 0, fmt.Errorf("custom rule line %d requires a unique id in 100000..199999", number+1)
		}
		seen[id] = true
		count++
	}
	return text, count, nil
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
