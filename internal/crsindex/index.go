package crsindex

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	SchemaVersion   = 1
	maxArchiveBytes = 256 << 20
	maxFileBytes    = 8 << 20
	maxPolicyBytes  = 64 << 20
)

type Source struct {
	Provider      string `json:"provider"`
	Repository    string `json:"repository"`
	Channel       string `json:"channel"`
	Version       string `json:"version"`
	Tag           string `json:"tag"`
	Commit        string `json:"commit"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

type Index struct {
	SchemaVersion int               `json:"schema_version"`
	GeneratedBy   string            `json:"generated_by"`
	Source        Source            `json:"source"`
	Statistics    Statistics        `json:"statistics"`
	Setup         []SetupField      `json:"setup"`
	SourceSetup   []SourceSetupItem `json:"source_setup,omitempty"`
	Files         []SourceFile      `json:"files,omitempty"`
	Directives    []SourceDirective `json:"directives,omitempty"`
	Rules         []Rule            `json:"rules"`
}

type Statistics struct {
	RuleCount      int            `json:"rule_count"`
	FileCount      int            `json:"file_count"`
	TotalFileCount int            `json:"total_file_count,omitempty"`
	DataFileCount  int            `json:"data_file_count,omitempty"`
	DirectiveCount int            `json:"directive_count,omitempty"`
	SetupKeyCount  int            `json:"setup_key_count,omitempty"`
	ByPhase        map[string]int `json:"by_phase"`
	ByPL           map[string]int `json:"by_paranoia_level"`
	ByTag          map[string]int `json:"by_tag"`
}

// SourceSetupItem describes every tx.* declaration present in the immutable
// upstream setup example. Managed is true only for values M-WAF can safely
// override when authoring a system policy.
type SourceSetupItem struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Line    int    `json:"line"`
	Active  bool   `json:"active"`
	Managed bool   `json:"managed"`
}

// SourceFile is a compact inventory entry. The original bytes remain in the
// verified archive; hashes and references are sufficient for version diffing.
type SourceFile struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	Size           int64  `json:"size"`
	LineCount      int    `json:"line_count"`
	SHA256         string `json:"sha256"`
	RuleCount      int    `json:"rule_count,omitempty"`
	DirectiveCount int    `json:"directive_count,omitempty"`
	ReferencedBy   []int  `json:"referenced_by,omitempty"`
}

// SourceDirective records executable CRS directives that are not represented
// by an ID-bearing Rule, such as markers and target exclusions.
type SourceDirective struct {
	Name           string   `json:"name"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	ContentHash    string   `json:"content_sha256"`
	Directive      string   `json:"directive"`
	RuleReferences []string `json:"rule_references,omitempty"`
}

type SetupField struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Default     string   `json:"default"`
	Minimum     int      `json:"minimum,omitempty"`
	Maximum     int      `json:"maximum,omitempty"`
	Options     []string `json:"options,omitempty"`
	Description string   `json:"description"`
}

type Rule struct {
	ID            int      `json:"id"`
	File          string   `json:"file"`
	Line          int      `json:"line"`
	Phase         string   `json:"phase,omitempty"`
	ParanoiaLevel int      `json:"paranoia_level,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Message       string   `json:"message,omitempty"`
	Variables     []string `json:"variables,omitempty"`
	Operator      string   `json:"operator,omitempty"`
	ContentHash   string   `json:"content_sha256"`
	Directive     string   `json:"directive"`
}

type logicalDirective struct {
	line int
	text string
}

var (
	ruleIDPattern    = regexp.MustCompile(`(?i)(?:^|,)\s*id\s*:\s*'?([0-9]+)'?`)
	phasePattern     = regexp.MustCompile(`(?i)(?:^|,)\s*phase\s*:\s*'?([0-9]+)'?`)
	severityPattern  = regexp.MustCompile(`(?i)(?:^|,)\s*severity\s*:\s*'?([^,']+)'?`)
	messagePattern   = regexp.MustCompile(`(?i)(?:^|,)\s*msg\s*:\s*'([^']*)'`)
	tagPattern       = regexp.MustCompile(`(?i)(?:^|,)\s*tag\s*:\s*'([^']*)'`)
	setupItemPattern = regexp.MustCompile(`(?i)setvar:\s*'?tx\.([a-z0-9_]+)=([^'\"]*)`)
)

func BuildFromArchive(reader io.Reader, source Source) (Index, error) {
	if source.Provider != "github" || source.Repository != "https://github.com/coreruleset/coreruleset" || (source.Channel != "stable" && source.Channel != "lts") || !strings.HasPrefix(source.Tag, "v4.") {
		return Index{}, errors.New("only official stable or LTS OWASP CRS v4 sources are supported")
	}
	if source.Version == "" || source.Commit == "" || len(source.ArchiveSHA256) != 64 {
		return Index{}, errors.New("CRS source version, commit and archive sha256 are required")
	}
	policyFiles, err := PolicyFilesFromArchive(reader)
	if err != nil {
		return Index{}, err
	}
	rules := make([]Rule, 0, 1000)
	files := make(map[string]bool)
	seenIDs := make(map[int]string)
	setupExample := string(policyFiles["crs/crs-setup.conf"])
	fileNames := make([]string, 0, len(policyFiles))
	for name := range policyFiles {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		relative := policyRelativePath(name)
		if !strings.HasPrefix(relative, "rules/") || !strings.HasSuffix(relative, ".conf") {
			continue
		}
		fileRules, err := parseRuleFile(relative, string(policyFiles[name]))
		if err != nil {
			return Index{}, err
		}
		files[relative] = true
		for _, rule := range fileRules {
			if previous, exists := seenIDs[rule.ID]; exists {
				return Index{}, fmt.Errorf("duplicate CRS rule id %d in %s and %s", rule.ID, previous, rule.File)
			}
			seenIDs[rule.ID] = rule.File
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return Index{}, errors.New("CRS archive contains no indexed rules")
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].ID == rules[j].ID {
			return rules[i].File < rules[j].File
		}
		return rules[i].ID < rules[j].ID
	})
	statistics := Statistics{RuleCount: len(rules), FileCount: len(files), ByPhase: map[string]int{}, ByPL: map[string]int{}, ByTag: map[string]int{}}
	for _, rule := range rules {
		statistics.ByPhase[rule.Phase]++
		statistics.ByPL[strconv.Itoa(rule.ParanoiaLevel)]++
		for _, tag := range rule.Tags {
			statistics.ByTag[tag]++
		}
	}
	setup, err := SupportedSetupFromExample(setupExample)
	if err != nil {
		return Index{}, err
	}
	index := Index{SchemaVersion: SchemaVersion, GeneratedBy: "mwaf-crs-index", Source: source, Statistics: statistics, Setup: setup, Rules: rules}
	return EnrichFromPolicyFiles(index, policyFiles), nil
}

// EnrichFromPolicyFiles adds complete, deterministic source inventory metadata
// to both new and legacy indexes without changing the immutable archive.
func EnrichFromPolicyFiles(index Index, files map[string][]byte) Index {
	result := index
	result.Files = nil
	result.Directives = nil
	result.SourceSetup = sourceSetupItems(string(files["crs/crs-setup.conf"]), index.Setup)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	filePositions := make(map[string]int, len(names))
	for _, name := range names {
		relative := policyRelativePath(name)
		raw := files[name]
		digest := sha256.Sum256(raw)
		item := SourceFile{Path: relative, Kind: sourceFileKind(relative), Size: int64(len(raw)), LineCount: sourceLineCount(raw), SHA256: hex.EncodeToString(digest[:])}
		if strings.HasSuffix(relative, ".conf") {
			for _, directive := range logicalDirectives(string(raw)) {
				fields := strings.Fields(directive.text)
				if len(fields) == 0 || fields[0] == "SecRule" || fields[0] == "SecAction" || !strings.HasPrefix(fields[0], "Sec") {
					continue
				}
				normalized := strings.Join(strings.Fields(directive.text), " ")
				hash := sha256.Sum256([]byte(normalized))
				entry := SourceDirective{Name: fields[0], File: relative, Line: directive.line, ContentHash: hex.EncodeToString(hash[:]), Directive: strings.TrimSpace(directive.text)}
				if len(fields) > 1 && fields[0] == "SecRuleUpdateTargetById" {
					entry.RuleReferences = splitRuleReferences(fields[1])
				}
				result.Directives = append(result.Directives, entry)
				item.DirectiveCount++
			}
		}
		filePositions[relative] = len(result.Files)
		result.Files = append(result.Files, item)
	}
	for _, rule := range result.Rules {
		if position, ok := filePositions[rule.File]; ok {
			result.Files[position].RuleCount++
		}
		for position := range result.Files {
			if result.Files[position].Kind == "data" && strings.Contains(rule.Directive, path.Base(result.Files[position].Path)) {
				result.Files[position].ReferencedBy = append(result.Files[position].ReferencedBy, rule.ID)
			}
		}
	}
	for position := range result.Files {
		result.Files[position].ReferencedBy = uniqueSortedInts(result.Files[position].ReferencedBy)
	}
	result.Statistics.FileCount = countSourceFiles(result.Files, "rule")
	result.Statistics.TotalFileCount = len(result.Files)
	result.Statistics.DataFileCount = countSourceFiles(result.Files, "data")
	result.Statistics.DirectiveCount = len(result.Directives)
	result.Statistics.SetupKeyCount = len(result.SourceSetup)
	return result
}

// PolicyFilesFromArchive returns the unchanged CRS files required by an Agent.
// Paths are rooted below crs/ so they can be staged inside one policy revision.
func PolicyFilesFromArchive(reader io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(io.LimitReader(reader, maxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("open CRS archive: %w", err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	files := make(map[string][]byte)
	var total int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read CRS archive: %w", err)
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		clean := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return nil, fmt.Errorf("unsafe CRS archive path %q", header.Name)
		}
		parts := strings.SplitN(clean, "/", 2)
		if len(parts) != 2 {
			continue
		}
		relative := parts[1]
		target := ""
		switch {
		case relative == "crs-setup.conf.example":
			target = "crs/crs-setup.conf"
		case strings.HasPrefix(relative, "rules/"):
			target = "crs/" + relative
		case relative == "LICENSE":
			target = "crs/LICENSE"
		default:
			continue
		}
		if header.Size < 0 || header.Size > maxFileBytes || total+header.Size > maxPolicyBytes {
			return nil, fmt.Errorf("CRS policy file %s exceeds the size limit", relative)
		}
		raw, err := io.ReadAll(io.LimitReader(archive, maxFileBytes+1))
		if err != nil || int64(len(raw)) != header.Size {
			return nil, fmt.Errorf("read CRS policy file %s", relative)
		}
		if _, exists := files[target]; exists {
			return nil, fmt.Errorf("duplicate CRS policy file %s", target)
		}
		files[target] = raw
		total += int64(len(raw))
	}
	if len(files) == 0 || files["crs/crs-setup.conf"] == nil {
		return nil, errors.New("CRS archive is missing policy files")
	}
	return files, nil
}

func SupportedSetup() []SetupField {
	return []SetupField{
		{Key: "blocking_paranoia_level", Label: "차단 실행 Paranoia Level", Type: "integer", Default: "1", Minimum: 1, Maximum: 4, Description: "차단 점수에 반영할 CRS 민감도"},
		{Key: "detection_paranoia_level", Label: "탐지 Paranoia Level", Type: "integer", Default: "1", Minimum: 1, Maximum: 4, Description: "실제로 실행해 탐지할 CRS 민감도"},
		{Key: "inbound_anomaly_score_threshold", Label: "Inbound 임계점수", Type: "integer", Default: "5", Minimum: 1, Maximum: 100, Description: "요청 차단 임계점수"},
		{Key: "outbound_anomaly_score_threshold", Label: "Outbound 임계점수", Type: "integer", Default: "4", Minimum: 1, Maximum: 100, Description: "응답 차단 임계점수"},
		{Key: "early_blocking", Label: "Early Blocking", Type: "boolean", Default: "0", Options: []string{"0", "1"}, Description: "최종 평가 전에 임계점수 도달 요청을 조기 차단"},
		{Key: "sampling_percentage", Label: "검사 샘플링 비율", Type: "integer", Default: "100", Minimum: 1, Maximum: 100, Description: "CRS 검사를 수행할 요청 비율"},
		{Key: "allowed_methods", Label: "허용 HTTP Method", Type: "list", Default: "GET HEAD POST OPTIONS", Description: "공백으로 구분한 허용 Method"},
		{Key: "allowed_request_content_type", Label: "허용 Content-Type", Type: "list", Default: "|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|", Description: "CRS 구분 형식으로 저장하는 허용 요청 Content-Type"},
		{Key: "allowed_http_versions", Label: "허용 HTTP 버전", Type: "list", Default: "HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0", Description: "공백으로 구분한 HTTP 버전"},
		{Key: "restricted_extensions", Label: "제한 확장자", Type: "list", Default: ".asa .asax .ascx .axd .backup .bak .bat .cdx .cer .cgi .cmd .com .config .conf .cs .csproj .csr .dat .db .dbf .dll .dos .htr .htw .ida .idc .idq .inc .ini .key .licx .lnk .log .mdb .old .pass .pdb .pol .printer .pwd .resources .resx .sql .sys .vb .vbs .vbproj .vsdisco .webinfo .xsd .xsx", Description: "접근을 제한할 파일 확장자"},
		{Key: "restricted_headers_basic", Label: "기본 제한 요청 헤더", Type: "list", Default: "/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/", Description: "일반 요청에서 기본으로 제한할 헤더"},
		{Key: "restricted_headers_extended", Label: "확장 제한 요청 헤더", Type: "list", Default: "/accept-charset/", Description: "호환성을 검토한 뒤 추가로 제한할 헤더"},
		{Key: "max_num_args", Label: "최대 인자 수", Type: "integer", Default: "255", Minimum: 1, Maximum: 10000, Description: "요청 인자 최대 개수"},
		{Key: "arg_name_length", Label: "인자 이름 최대 길이", Type: "integer", Default: "100", Minimum: 1, Maximum: 10000, Description: "요청 인자 이름 최대 길이"},
		{Key: "total_arg_length", Label: "전체 인자 최대 길이", Type: "integer", Default: "64000", Minimum: 1, Maximum: 10000000, Description: "전체 요청 인자 길이 제한"},
		{Key: "max_file_size", Label: "단일 파일 최대 크기", Type: "integer", Default: "unlimited", Minimum: 1, Maximum: 1073741824, Description: "업로드 파일 단위 최대 크기 또는 unlimited"},
		{Key: "combined_file_sizes", Label: "전체 파일 최대 크기", Type: "integer", Default: "unlimited", Minimum: 1, Maximum: 1073741824, Description: "한 요청의 전체 업로드 크기 또는 unlimited"},
	}
}

// NormalizeSupportedSetup applies the reviewed M-WAF defaults to indexes made
// before setup comments and example overrides were distinguished. The source
// release remains immutable; only the authoring metadata shown to operators is
// repaired in memory.
func NormalizeSupportedSetup(fields []SetupField) []SetupField {
	reviewed := make(map[string]SetupField)
	for _, field := range SupportedSetup() {
		reviewed[field.Key] = field
	}
	result := make([]SetupField, len(fields))
	copy(result, fields)
	for index := range result {
		if field, ok := reviewed[result[index].Key]; ok {
			result[index].Default = field.Default
			if result[index].Label == "" {
				result[index].Label = field.Label
			}
		}
	}
	return result
}

func SupportedSetupFromExample(raw string) ([]SetupField, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("CRS archive is missing crs-setup.conf.example")
	}
	defined := make(map[string]bool)
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		marker := strings.Index(strings.ToLower(line), "setvar:")
		if marker < 0 {
			continue
		}
		value := strings.TrimSpace(line[marker+len("setvar:"):])
		quoted := strings.HasPrefix(value, "'")
		value = strings.TrimPrefix(value, "'")
		if !strings.HasPrefix(strings.ToLower(value), "tx.") {
			continue
		}
		key, remainder, ok := strings.Cut(strings.TrimPrefix(value, "tx."), "=")
		if !ok {
			continue
		}
		if quoted {
			remainder, _, _ = strings.Cut(remainder, "'")
		} else {
			remainder = strings.TrimRight(remainder, "\\,\"")
		}
		key = strings.TrimSpace(key)
		remainder = strings.TrimSpace(remainder)
		if key != "" && remainder != "" {
			defined[key] = true
		}
	}
	fields := SupportedSetup()
	for index := range fields {
		if !defined[fields[index].Key] {
			return nil, fmt.Errorf("CRS setup example does not define supported key %s", fields[index].Key)
		}
	}
	return fields, nil
}

func sourceSetupItems(raw string, managedFields []SetupField) []SourceSetupItem {
	managed := make(map[string]bool, len(managedFields))
	for _, field := range managedFields {
		managed[field.Key] = true
	}
	items := make(map[string]SourceSetupItem)
	for index, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		match := setupItemPattern.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		key := strings.TrimSpace(match[1])
		value := strings.TrimSpace(strings.TrimRight(match[2], "\\, \t"))
		if key == "" || value == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		item := SourceSetupItem{Key: key, Value: value, Line: index + 1, Active: !strings.HasPrefix(trimmed, "#"), Managed: managed[key]}
		previous, exists := items[key]
		if !exists || item.Active && !previous.Active {
			items[key] = item
		}
	}
	result := make([]SourceSetupItem, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

func policyRelativePath(name string) string {
	return strings.TrimPrefix(path.Clean(strings.TrimPrefix(name, "./")), "crs/")
}

func sourceFileKind(name string) string {
	switch {
	case name == "crs-setup.conf":
		return "setup"
	case name == "LICENSE":
		return "license"
	case strings.HasSuffix(name, ".data"):
		return "data"
	case strings.HasSuffix(name, ".conf.example"):
		return "example"
	case strings.HasSuffix(name, ".conf"):
		return "rule"
	default:
		return "other"
	}
}

func sourceLineCount(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	lines := bytesCount(raw, '\n')
	if raw[len(raw)-1] != '\n' {
		lines++
	}
	return lines
}

func bytesCount(raw []byte, value byte) int {
	count := 0
	for _, current := range raw {
		if current == value {
			count++
		}
	}
	return count
}

func splitRuleReferences(value string) []string {
	value = strings.Trim(value, "'\"")
	parts := strings.FieldsFunc(value, func(char rune) bool { return char == ',' || char == '|' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return uniqueSortedStrings(result)
}

func uniqueSortedInts(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value == 0 || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func countSourceFiles(files []SourceFile, kind string) int {
	count := 0
	for _, file := range files {
		if file.Kind == kind {
			count++
		}
	}
	return count
}

func parseRuleFile(name, raw string) ([]Rule, error) {
	directives := logicalDirectives(raw)
	rules := make([]Rule, 0)
	for index := 0; index < len(directives); index++ {
		directive := directives[index]
		trimmed := strings.TrimSpace(directive.text)
		if !strings.HasPrefix(trimmed, "SecRule ") && !strings.HasPrefix(trimmed, "SecAction ") {
			continue
		}
		idMatch := ruleIDPattern.FindStringSubmatch(actionsFromDirective(trimmed))
		if len(idMatch) != 2 {
			return nil, fmt.Errorf("CRS directive in %s:%d is missing a Rule ID", name, directive.line)
		}
		id, _ := strconv.Atoi(idMatch[1])
		combined := trimmed
		chained := hasChainAction(trimmed)
		for chained && index+1 < len(directives) {
			index++
			next := strings.TrimSpace(directives[index].text)
			combined += "\n" + next
			chained = hasChainAction(next)
		}
		rule := ruleMetadata(name, directive.line, id, combined)
		rules = append(rules, rule)
	}
	return rules, nil
}

func logicalDirectives(raw string) []logicalDirective {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	items := make([]logicalDirective, 0, len(lines))
	var current strings.Builder
	start := 0
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if current.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			start = index + 1
		}
		continued := strings.HasSuffix(trimmed, "\\")
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		if current.Len() != 0 {
			current.WriteByte(' ')
		}
		current.WriteString(trimmed)
		if continued {
			continue
		}
		items = append(items, logicalDirective{line: start, text: current.String()})
		current.Reset()
	}
	if current.Len() != 0 {
		items = append(items, logicalDirective{line: start, text: current.String()})
	}
	return items
}

func ruleMetadata(file string, line, id int, directive string) Rule {
	actions := actionsFromDirective(strings.SplitN(directive, "\n", 2)[0])
	rule := Rule{ID: id, File: file, Line: line, Directive: directive}
	if match := phasePattern.FindStringSubmatch(actions); len(match) == 2 {
		rule.Phase = match[1]
	}
	if match := severityPattern.FindStringSubmatch(actions); len(match) == 2 {
		rule.Severity = strings.TrimSpace(match[1])
	}
	if match := messagePattern.FindStringSubmatch(actions); len(match) == 2 {
		rule.Message = match[1]
	}
	for _, match := range tagPattern.FindAllStringSubmatch(actions, -1) {
		if len(match) != 2 {
			continue
		}
		rule.Tags = append(rule.Tags, match[1])
		if strings.HasPrefix(match[1], "paranoia-level/") {
			rule.ParanoiaLevel, _ = strconv.Atoi(strings.TrimPrefix(match[1], "paranoia-level/"))
		}
	}
	firstLine := strings.SplitN(directive, "\n", 2)[0]
	if strings.HasPrefix(firstLine, "SecRule ") {
		body := strings.TrimSpace(strings.TrimPrefix(firstLine, "SecRule "))
		quote := strings.Index(body, `"`)
		if quote > 0 {
			variables := strings.TrimSpace(body[:quote])
			for _, variable := range strings.Split(variables, "|") {
				if value := strings.TrimSpace(variable); value != "" {
					rule.Variables = append(rule.Variables, value)
				}
			}
			quoted := quotedValues(body[quote:])
			if len(quoted) > 0 {
				rule.Operator = quoted[0]
			}
		}
	}
	normalized := strings.Join(strings.Fields(directive), " ")
	digest := sha256.Sum256([]byte(normalized))
	rule.ContentHash = hex.EncodeToString(digest[:])
	rule.Tags = uniqueSortedStrings(rule.Tags)
	rule.Variables = uniqueSortedStrings(rule.Variables)
	return rule
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func actionsFromDirective(directive string) string {
	values := quotedValues(directive)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func quotedValues(text string) []string {
	values := make([]string, 0, 3)
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, char := range text {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' && inQuote {
			escaped = true
			current.WriteRune(char)
			continue
		}
		if char != '"' {
			if inQuote {
				current.WriteRune(char)
			}
			continue
		}
		if inQuote {
			values = append(values, current.String())
			current.Reset()
		}
		inQuote = !inQuote
	}
	return values
}

func hasChainAction(directive string) bool {
	actions := strings.ToLower(actionsFromDirective(strings.SplitN(directive, "\n", 2)[0]))
	for _, action := range strings.Split(actions, ",") {
		if strings.TrimSpace(action) == "chain" {
			return true
		}
	}
	return false
}
