package manager

import "testing"

func TestCRSRuleOperatorName(t *testing.T) {
	tests := map[string]string{
		"":                             "",
		"@rx select":                   "@rx",
		"!@rx ^application/json$":      "!@rx",
		"@pmFromFile restricted.data":  "@pmFromFile",
		"(?i)select[[:space:]]+from":   "@rx",
		"!^(?:GET|HEAD|POST|OPTIONS)$": "!@rx",
	}
	for input, expected := range tests {
		if actual := crsRuleOperatorName(input); actual != expected {
			t.Errorf("crsRuleOperatorName(%q) = %q, want %q", input, actual, expected)
		}
	}
}
