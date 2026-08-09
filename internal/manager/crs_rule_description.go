package manager

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
)

func describeCRSRule(rule crsindex.Rule) string {
	if rule.ID == 901001 {
		return "CRS Setup 파일이 웹서버에 먼저 로드되었는지 확인합니다. Setup 정보가 없으면 잘못된 CRS 설치로 판단해 설정 오류를 기록하는 초기 점검 규칙입니다."
	}
	if strings.Contains(rule.File, "REQUEST-901-INITIALIZATION") {
		return describeCRSInitializationRule(rule)
	}
	if strings.Contains(rule.Directive, "skipAfter:") && containsRuleVariable(rule.Variables, "PARANOIA_LEVEL") {
		return fmt.Sprintf("현재 Paranoia Level을 확인해 실행하지 않을 Rule 구간을 건너뛰는 CRS 제어 규칙입니다. %s에서 설정된 민감도에 해당하는 Rule만 실행되도록 합니다.", koreanRulePhase(rule.Phase))
	}

	purpose := koreanRulePurpose(rule)
	target := koreanRuleTargets(rule.Variables)
	phase := koreanRulePhase(rule.Phase)
	if target == "" {
		return fmt.Sprintf("%s %s에서 실행되며 탐지 결과를 정책의 이상 점수와 최종 차단 판단에 반영합니다.", purpose, phase)
	}
	return fmt.Sprintf("%s 검사 대상은 %s이며, %s에서 탐지 결과를 정책의 이상 점수와 최종 차단 판단에 반영합니다.", purpose, target, phase)
}

func describeCRSInitializationRule(rule crsindex.Rule) string {
	setting := "CRS 내부 설정"
	variable := ""
	if len(rule.Variables) != 0 {
		variable = rule.Variables[0]
		setting = koreanCRSSetting(variable)
	}
	if strings.HasPrefix(strings.TrimSpace(rule.Operator), "@eq") || strings.Contains(variable, "&TX:") {
		return fmt.Sprintf("%s이(가) 설정되어 있는지 확인하고, 값이 없으면 CRS 기본값을 준비하는 초기화 규칙입니다. 실제 공격을 탐지하는 Rule이 아니라 이후 Rule이 사용할 실행 환경을 구성합니다.", setting)
	}
	return fmt.Sprintf("%s을(를) 계산하거나 정규화해 이후 탐지 Rule이 사용할 CRS 실행 환경을 준비하는 초기화 규칙입니다.", setting)
}

func koreanRulePurpose(rule crsindex.Rule) string {
	tags := make(map[string]bool, len(rule.Tags))
	for _, tag := range rule.Tags {
		tags[strings.ToLower(tag)] = true
	}
	for _, candidate := range []struct {
		tag  string
		text string
	}{
		{"attack-sqli", "SQL 삽입 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-xss", "크로스 사이트 스크립팅(XSS) 패턴을 탐지하는 규칙입니다."},
		{"attack-rce", "원격 명령·코드 실행 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-lfi", "로컬 파일 포함 및 경로 탐색 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-rfi", "외부 파일 포함 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-ssrf", "서버 측 요청 위조(SSRF) 패턴을 탐지하는 규칙입니다."},
		{"attack-ssti", "서버 측 템플릿 삽입(SSTI) 패턴을 탐지하는 규칙입니다."},
		{"attack-injection-php", "PHP 코드 삽입과 위험 함수 호출 패턴을 탐지하는 규칙입니다."},
		{"attack-injection-java", "Java 코드·표현식 삽입 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-injection-generic", "일반적인 코드·명령 삽입 공격 패턴을 탐지하는 규칙입니다."},
		{"attack-fixation", "세션 고정 공격에 사용되는 파라미터와 쿠키 패턴을 탐지하는 규칙입니다."},
		{"attack-multipart-header", "비정상 multipart 요청 구조와 헤더 조작을 탐지하는 규칙입니다."},
		{"attack-reputation-scanner", "알려진 보안 스캐너와 자동화 도구의 요청 특징을 탐지하는 규칙입니다."},
		{"attack-protocol", "HTTP 프로토콜을 악용하거나 우회하려는 비정상 요청을 탐지하는 규칙입니다."},
		{"attack-disclosure", "응답에 노출된 오류·시스템·소스 정보 패턴을 탐지하는 규칙입니다."},
		{"attack-deprecated-header", "사용 중단되었거나 위험한 HTTP 헤더 사용을 탐지하는 규칙입니다."},
		{"header-allowlist", "허용 목록에 없는 HTTP 헤더를 탐지하는 규칙입니다."},
		{"anomaly-evaluation", "누적된 이상 점수를 임계값과 비교해 차단 여부를 판정하는 규칙입니다."},
		{"reporting", "탐지·차단 결과를 감사 로그에 정리하는 규칙입니다."},
	} {
		if tags[candidate.tag] {
			return candidate.text
		}
	}

	filePurposes := []struct {
		marker string
		text   string
	}{
		{"REQUEST-905", "일반적인 정상 요청을 CRS 검사에서 안전하게 제외하는 공통 예외 규칙입니다."},
		{"REQUEST-911", "허용하지 않은 HTTP 메서드 사용을 탐지하는 규칙입니다."},
		{"REQUEST-913", "보안 스캐너와 자동화 공격 도구의 요청 특징을 탐지하는 규칙입니다."},
		{"REQUEST-920", "HTTP 요청 형식, 헤더와 인코딩이 보안 기준을 위반하는지 검사하는 규칙입니다."},
		{"REQUEST-921", "HTTP 요청 분할·스머글링 등 프로토콜 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-922", "multipart 요청의 비정상 구조와 파일 업로드 조작을 탐지하는 규칙입니다."},
		{"REQUEST-930", "로컬 파일 포함 및 경로 탐색 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-931", "외부 파일 포함 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-932", "운영체제 명령과 원격 코드 실행 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-933", "PHP 코드 삽입과 위험 함수 호출 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-934", "SSRF·SSTI 등 일반 웹 애플리케이션 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-941", "크로스 사이트 스크립팅(XSS) 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-942", "SQL 삽입 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-943", "세션 고정 공격 패턴을 탐지하는 규칙입니다."},
		{"REQUEST-944", "Java 애플리케이션을 대상으로 한 코드 실행·삽입 공격을 탐지하는 규칙입니다."},
		{"REQUEST-949", "요청 단계에서 누적된 이상 점수를 기준으로 최종 차단 여부를 판정하는 규칙입니다."},
		{"RESPONSE-950", "응답 본문에 노출된 민감 정보와 오류 메시지를 탐지하는 규칙입니다."},
		{"RESPONSE-951", "응답에 노출된 데이터베이스와 SQL 오류 정보를 탐지하는 규칙입니다."},
		{"RESPONSE-952", "응답에 노출된 Java 오류와 시스템 정보를 탐지하는 규칙입니다."},
		{"RESPONSE-953", "응답에 노출된 PHP 오류와 시스템 정보를 탐지하는 규칙입니다."},
		{"RESPONSE-954", "응답에 노출된 IIS 오류와 시스템 정보를 탐지하는 규칙입니다."},
		{"RESPONSE-955", "응답 본문에 포함된 웹셸 동작과 출력 패턴을 탐지하는 규칙입니다."},
		{"RESPONSE-956", "응답에 노출된 Ruby 오류와 시스템 정보를 탐지하는 규칙입니다."},
		{"RESPONSE-959", "응답 단계에서 누적된 이상 점수를 기준으로 최종 차단 여부를 판정하는 규칙입니다."},
		{"RESPONSE-980", "요청과 응답의 탐지 결과를 연결해 최종 감사 정보를 기록하는 규칙입니다."},
	}
	for _, candidate := range filePurposes {
		if strings.Contains(rule.File, candidate.marker) {
			return candidate.text
		}
	}
	return "OWASP CRS가 정의한 비정상 요청 또는 응답 패턴을 탐지하는 규칙입니다."
}

func koreanRuleTargets(variables []string) string {
	labels := make(map[string]bool)
	for _, variable := range variables {
		upper := strings.ToUpper(variable)
		switch {
		case strings.Contains(upper, "RESPONSE_BODY"):
			labels["응답 본문"] = true
		case strings.Contains(upper, "RESPONSE_HEADERS"):
			labels["응답 헤더"] = true
		case strings.Contains(upper, "REQUEST_COOKIES"):
			labels["쿠키"] = true
		case strings.Contains(upper, "REQUEST_HEADERS"):
			labels["요청 헤더"] = true
		case strings.Contains(upper, "REQUEST_METHOD"):
			labels["HTTP 메서드"] = true
		case strings.Contains(upper, "REQUEST_URI"), strings.Contains(upper, "REQUEST_FILENAME"), strings.Contains(upper, "REQUEST_BASENAME"):
			labels["요청 URL·파일 경로"] = true
		case strings.Contains(upper, "ARGS"):
			labels["요청 파라미터"] = true
		case strings.Contains(upper, "XML"):
			labels["XML 입력"] = true
		case strings.Contains(upper, "FILES"):
			labels["업로드 파일"] = true
		case strings.Contains(upper, "MULTIPART"):
			labels["multipart 요청"] = true
		case strings.Contains(upper, "REMOTE_ADDR"):
			labels["접속 IP"] = true
		case strings.Contains(upper, "REQUEST_LINE"):
			labels["HTTP 요청 라인"] = true
		case strings.Contains(upper, "TX:"):
			labels["CRS 내부 상태"] = true
		}
	}
	result := make([]string, 0, len(labels))
	for label := range labels {
		result = append(result, label)
	}
	sort.Strings(result)
	if len(result) > 3 {
		result = append(result[:3], "기타 입력")
	}
	return strings.Join(result, "·")
}

func koreanRulePhase(phase string) string {
	switch phase {
	case "1":
		return "phase 1(요청 헤더 초기 처리)"
	case "2":
		return "phase 2(요청 본문 처리)"
	case "3":
		return "phase 3(응답 헤더 처리)"
	case "4":
		return "phase 4(응답 본문 처리)"
	case "5":
		return "phase 5(로그·마무리 처리)"
	default:
		return "CRS 처리 단계"
	}
}

func containsRuleVariable(variables []string, value string) bool {
	for _, variable := range variables {
		if strings.Contains(strings.ToUpper(variable), value) {
			return true
		}
	}
	return false
}

func koreanCRSSetting(variable string) string {
	key := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(variable, "&"), "TX:"))
	labels := map[string]string{
		"crs_setup_version":                "CRS Setup 버전",
		"inbound_anomaly_score_threshold":  "요청 차단 임계점수",
		"outbound_anomaly_score_threshold": "응답 차단 임계점수",
		"reporting_level":                  "감사 보고 수준",
		"early_blocking":                   "조기 차단 설정",
		"blocking_paranoia_level":          "차단 Paranoia Level",
		"detection_paranoia_level":         "탐지 Paranoia Level",
		"sampling_percentage":              "검사 샘플링 비율",
		"critical_anomaly_score":           "CRITICAL 위험 점수",
		"error_anomaly_score":              "ERROR 위험 점수",
		"warning_anomaly_score":            "WARNING 위험 점수",
		"notice_anomaly_score":             "NOTICE 위험 점수",
		"allowed_methods":                  "허용 HTTP 메서드",
		"allowed_request_content_type":     "허용 요청 Content-Type",
		"allowed_http_versions":            "허용 HTTP 버전",
		"restricted_extensions":            "제한 파일 확장자",
		"restricted_headers_basic":         "기본 제한 요청 헤더",
		"restricted_headers_extended":      "확장 제한 요청 헤더",
	}
	if label := labels[key]; label != "" {
		return label
	}
	if key == "" {
		return "CRS 내부 설정"
	}
	return "CRS 내부 설정 tx." + key
}
