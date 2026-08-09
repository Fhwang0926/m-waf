package manager

import (
	"strings"
	"testing"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
)

func TestDescribeCRSRuleInKorean(t *testing.T) {
	tests := []struct {
		name string
		rule crsindex.Rule
		want []string
	}{
		{
			name: "setup missing",
			rule: crsindex.Rule{ID: 901001, File: "rules/REQUEST-901-INITIALIZATION.conf"},
			want: []string{"CRS Setup", "초기 점검"},
		},
		{
			name: "setup default",
			rule: crsindex.Rule{ID: 901100, File: "rules/REQUEST-901-INITIALIZATION.conf", Variables: []string{"&TX:inbound_anomaly_score_threshold"}, Operator: "@eq 0"},
			want: []string{"요청 차단 임계점수", "초기화"},
		},
		{
			name: "sql injection",
			rule: crsindex.Rule{ID: 942100, File: "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Phase: "2", Tags: []string{"attack-sqli"}, Variables: []string{"ARGS", "REQUEST_COOKIES"}},
			want: []string{"SQL 삽입", "요청 파라미터", "phase 2"},
		},
		{
			name: "paranoia level guard",
			rule: crsindex.Rule{ID: 942011, File: "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Phase: "1", Variables: []string{"TX:DETECTION_PARANOIA_LEVEL"}, Directive: "SecRule ... skipAfter:END-REQUEST-942"},
			want: []string{"Paranoia Level", "건너뛰"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			description := describeCRSRule(test.rule)
			for _, expected := range test.want {
				if !strings.Contains(description, expected) {
					t.Fatalf("description %q does not contain %q", description, expected)
				}
			}
		})
	}
}
