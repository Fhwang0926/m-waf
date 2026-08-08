package manager

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const (
	openSourceRulePageSize = 50
	openSourceListPageSize = 20
)

type openSourcePolicyView struct {
	Source                    model.PolicySourceArtifact `json:"source"`
	Statistics                crsindex.Statistics        `json:"statistics"`
	SetupCount                int                        `json:"setup_count"`
	BaseSystemPolicyID        string                     `json:"base_system_policy_id,omitempty"`
	Status                    string                     `json:"status"`
	SystemPolicyCount         int                        `json:"system_policy_count"`
	EnterpriseCount           int                        `json:"enterprise_count"`
	AgentPackageCount         int                        `json:"agent_package_count"`
	ModulePackageCount        int                        `json:"module_package_count"`
	ReleaseStatus             string                     `json:"release_status"`
	DBIndexReady              bool                       `json:"db_index_ready"`
	VerifiedAt                time.Time                  `json:"verified_at,omitempty"`
	LinkStatus                string                     `json:"link_status"`
	LinkedSystemPolicyID      string                     `json:"linked_system_policy_id,omitempty"`
	LinkedSystemPolicyVersion string                     `json:"linked_system_policy_version,omitempty"`
	CanMigrate                bool                       `json:"can_migrate"`
	MigrationBlockReason      string                     `json:"migration_block_reason,omitempty"`
}

func (v openSourcePolicyView) StatusLabel() string {
	switch v.LinkStatus {
	case "CURRENT":
		return "현재 연동"
	case "LEGACY_UNPINNED":
		return "연동 정보 보완 필요"
	case "PREVIOUS":
		return "이전 사용"
	case "BLOCKED":
		return "반영 차단"
	default:
		return "전환 가능"
	}
}

func (v openSourcePolicyView) StatusClass() string {
	if v.LinkStatus == "CURRENT" {
		return "ok"
	}
	if v.LinkStatus == "AVAILABLE" {
		return "info"
	}
	if v.LinkStatus == "BLOCKED" {
		return "danger"
	}
	return "warn"
}

func (v openSourcePolicyView) PackagesReady() bool {
	return v.Source.ArtifactFormat == "policy-bundle-v3" || v.AgentPackageCount > 0 && v.ModulePackageCount > 0
}

func (v openSourcePolicyView) SelfContained() bool {
	return v.Source.ArtifactFormat == "policy-bundle-v3"
}

type openSourcePolicyLifecycle struct {
	HasSources             bool
	HasCurrent             bool
	HasNewSource           bool
	CurrentPolicyVersion   string
	CurrentPolicyReference string
	CurrentCRSVersion      string
	CurrentCRSChannel      string
	CurrentSourceID        string
	CurrentLinkStatus      string
	LastCheckedAt          time.Time
	LatestSourceID         string
	LatestSourceVersion    string
	LatestSourceTag        string
	LatestPackagesReady    bool
}

type openSourcePolicyList struct {
	Items      []openSourcePolicyView
	Total      int
	Page       int
	PageSize   int
	HasNext    bool
	Query      string
	Channel    string
	LinkStatus string
}

func (l openSourcePolicyList) pageURL(page int) string {
	values := url.Values{}
	if l.Query != "" {
		values.Set("q", l.Query)
	}
	if l.Channel != "" {
		values.Set("channel", l.Channel)
	}
	if l.LinkStatus != "" {
		values.Set("link_status", l.LinkStatus)
	}
	values.Set("page", strconv.Itoa(page))
	return "/open-source-policies?" + values.Encode()
}

func (l openSourcePolicyList) PreviousURL() string {
	if l.Page <= 1 {
		return ""
	}
	return l.pageURL(l.Page - 1)
}

func (l openSourcePolicyList) NextURL() string {
	if !l.HasNext {
		return ""
	}
	return l.pageURL(l.Page + 1)
}

type openSourceRuleView struct {
	crsindex.Rule
	GitHubURL string `json:"github_url"`
}

type openSourcePolicyDetail struct {
	Policy         openSourcePolicyView  `json:"policy"`
	Setup          []crsindex.SetupField `json:"setup"`
	Rules          []openSourceRuleView  `json:"rules"`
	Page           int                   `json:"page"`
	PageSize       int                   `json:"page_size"`
	Total          int                   `json:"total"`
	HasNext        bool                  `json:"has_next"`
	FilterQ        string                `json:"-"`
	FilterID       string                `json:"-"`
	FilterFile     string                `json:"-"`
	FilterTag      string                `json:"-"`
	FilterPL       string                `json:"-"`
	FilterPhase    string                `json:"-"`
	FilterSeverity string                `json:"-"`
}

func (d openSourcePolicyDetail) pageURL(page int) string {
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	for key, value := range map[string]string{"q": d.FilterQ, "rule_id": d.FilterID, "file": d.FilterFile, "tag": d.FilterTag, "severity": d.FilterSeverity, "phase": d.FilterPhase, "paranoia_level": d.FilterPL} {
		if value != "" {
			values.Set(key, value)
		}
	}
	return "/open-source-policies/" + url.PathEscape(d.Policy.Source.ID) + "?" + values.Encode()
}

func (d openSourcePolicyDetail) PreviousURL() string {
	if d.Page <= 1 {
		return ""
	}
	return d.pageURL(d.Page - 1)
}

func (d openSourcePolicyDetail) NextURL() string {
	if !d.HasNext {
		return ""
	}
	return d.pageURL(d.Page + 1)
}

type sourceRuleDiff struct {
	Added   []crsindex.Rule `json:"added"`
	Removed []crsindex.Rule `json:"removed"`
	Changed []crsindex.Rule `json:"changed"`
}

type sourceSetupDiff struct {
	Key      string `json:"key"`
	Change   string `json:"change"`
	Previous string `json:"previous,omitempty"`
	Next     string `json:"next,omitempty"`
}

type openSourcePolicyDiff struct {
	SourceID           string            `json:"source_id"`
	BaseSystemPolicyID string            `json:"base_system_policy_id"`
	Rules              sourceRuleDiff    `json:"rules"`
	Setup              []sourceSetupDiff `json:"setup"`
}

func (s *Server) openSourcePolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.openSourcePolicyList(r)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "오픈소스 CRS 카탈로그를 불러올 수 없습니다", err.Error())
		return
	}
	lifecycle := s.openSourceLifecycle(r, list.Items)
	data := map[string]any{"Policies": list.Items, "List": list, "Lifecycle": lifecycle, "CatalogError": s.catalogErr, "CRSSyncInterval": s.cfg.CRSSyncInterval}
	if r.URL.Query().Get("setup") == "1" {
		data["Notice"] = "시스템 관리자 설정이 완료되었습니다. 공식 OWASP CRS를 연동한 뒤 최초 시스템 정책을 검토·게시하세요."
	} else if r.URL.Query().Get("synced") == "1" {
		channel := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("channel")))
		if channel == "" || channel == "ALL" {
			channel = "LTS·Stable"
		}
		data["Notice"] = "공식 OWASP CRS " + channel + " v4 소스를 확인하고 검증된 원본을 Manager에 저장했습니다."
	} else if r.URL.Query().Get("current") == "1" {
		data["Notice"] = "현재 Manager가 최신 검증 CRS 소스를 보유하고 있습니다."
	}
	_ = s.templates.ExecuteTemplate(w, "open-source-policies.html", s.viewData(r, "open-source-policies", data))
}

func (s *Server) openSourcePolicyDetail(w http.ResponseWriter, r *http.Request) {
	detail, found, err := s.openSourcePolicyDetailData(r)
	if err != nil {
		s.renderAdminError(w, r, http.StatusInternalServerError, "CRS 상세 정보를 불러올 수 없습니다", err.Error())
		return
	}
	if !found {
		s.renderAdminError(w, r, http.StatusNotFound, "검증된 CRS 소스를 찾을 수 없습니다", "Manager가 검증·보존한 공식 stable v4 소스만 관리할 수 있습니다.")
		return
	}
	base := s.defaultSystemPolicyTemplate(r.Context())
	detail.Policy = classifyOpenSourcePolicyView(detail.Policy, base)
	baseID := ""
	if base.Key != "" {
		baseID = base.Reference()
	}
	diff, _, _ := s.openSourceDiff(r, detail.Policy.Source.ID, baseID)
	_ = s.templates.ExecuteTemplate(w, "open-source-policy.html", s.viewData(r, "open-source-policies", map[string]any{"Detail": detail, "Base": base, "HasBase": base.Key != "", "Diff": diff}))
}

func (s *Server) apiOpenSourcePolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.openSourcePolicyList(r)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list.Items, "page": list.Page, "page_size": list.PageSize, "total": list.Total, "has_next": list.HasNext})
}

func (s *Server) apiOpenSourcePolicy(w http.ResponseWriter, r *http.Request) {
	sourceID := r.PathValue("source_id")
	source, index, ok, err := s.indexedPolicySource(r.Context(), sourceID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeProblem(w, http.StatusNotFound, "verified policy source not found")
		return
	}
	view, err := s.openSourcePolicyView(r, source, index)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, err.Error())
		return
	}
	view = classifyOpenSourcePolicyView(view, s.defaultSystemPolicyTemplate(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"policy": view, "setup": index.Setup})
}

func (s *Server) apiOpenSourcePolicyRules(w http.ResponseWriter, r *http.Request) {
	detail, found, err := s.openSourcePolicyDetailData(r)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "verified policy source not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": detail.Rules, "page": detail.Page, "page_size": detail.PageSize, "total": detail.Total, "has_next": detail.HasNext})
}

func (s *Server) apiOpenSourcePolicyDiff(w http.ResponseWriter, r *http.Request) {
	diff, found, err := s.openSourceDiff(r, r.PathValue("source_id"), strings.TrimSpace(r.URL.Query().Get("base_system_policy_id")))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	if !found {
		writeProblem(w, http.StatusNotFound, "verified policy source not found")
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) openSourcePolicyList(r *http.Request) (openSourcePolicyList, error) {
	items := make([]openSourcePolicyView, 0)
	channel := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("channel")))
	if channel == "all" {
		channel = ""
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	linkStatus := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("link_status")))
	if linkStatus == "ALL" {
		linkStatus = ""
	}
	current := s.defaultSystemPolicyTemplate(r.Context())
	for _, source := range s.allPolicySources() {
		if channel != "" && source.Channel != channel {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{source.Version, source.Tag, source.Commit, source.Channel}, " ")), query) {
			continue
		}
		_, index, ok, err := s.indexedPolicySource(r.Context(), source.ID)
		if err != nil {
			return openSourcePolicyList{}, err
		}
		if !ok {
			continue
		}
		view, err := s.openSourcePolicyView(r, source, index)
		if err != nil {
			return openSourcePolicyList{}, err
		}
		view = classifyOpenSourcePolicyView(view, current)
		if linkStatus != "" && view.LinkStatus != linkStatus {
			continue
		}
		items = append(items, view)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if normalizeCRSVersion(items[i].Source.Version) == normalizeCRSVersion(items[j].Source.Version) {
			return items[i].Source.Channel == "stable" && items[j].Source.Channel != "stable"
		}
		return newerCRSVersion(items[i].Source.Version, items[j].Source.Version)
	})
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	start := (page - 1) * openSourceListPageSize
	if start > len(items) {
		start = len(items)
	}
	end := start + openSourceListPageSize
	if end > len(items) {
		end = len(items)
	}
	return openSourcePolicyList{
		Items: items[start:end], Total: len(items), Page: page, PageSize: openSourceListPageSize, HasNext: end < len(items),
		Query: r.URL.Query().Get("q"), Channel: channel, LinkStatus: linkStatus,
	}, nil
}

func (s *Server) openSourcePolicyViews(r *http.Request) ([]openSourcePolicyView, error) {
	list, err := s.openSourcePolicyList(r)
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func classifyOpenSourcePolicyView(view openSourcePolicyView, current systempolicy.Template) openSourcePolicyView {
	view.Status = "AVAILABLE"
	view.LinkStatus = "AVAILABLE"
	view.CanMigrate = true
	if current.Key == "" {
		applySourceReadiness(&view)
		return view
	}
	view.BaseSystemPolicyID = current.Reference()
	if exactSourceMatchesSystemPolicy(view.Source, current) {
		view.Status, view.LinkStatus, view.CanMigrate = "CURRENT", "CURRENT", false
		view.LinkedSystemPolicyID, view.LinkedSystemPolicyVersion = current.Reference(), current.Version
		view.MigrationBlockReason = "현재 기준 정책에 정확히 연동된 CRS입니다."
		return view
	}
	ref := current.Defaults.CRSSource
	unpinned := ref == nil || ref.ID == "" || ref.ArchiveSHA256 == "" || ref.IndexSHA256 == ""
	if unpinned && normalizeCRSVersion(view.Source.Version) == normalizeCRSVersion(current.CRSVersion) {
		view.Status, view.LinkStatus, view.CanMigrate = "LEGACY_UNPINNED", "LEGACY_UNPINNED", true
		view.LinkedSystemPolicyID, view.LinkedSystemPolicyVersion = current.Reference(), current.Version
		applySourceReadiness(&view)
		return view
	}
	if view.LinkedSystemPolicyID != "" {
		view.Status, view.LinkStatus = "PREVIOUS", "PREVIOUS"
	}
	if strings.EqualFold(view.Source.Channel, current.CRSTrack) && !newerCRSVersion(view.Source.Version, current.CRSVersion) {
		view.CanMigrate = false
		view.MigrationBlockReason = "같은 채널의 현재 버전보다 낮거나 같은 CRS는 일반 마이그레이션 대상이 아닙니다."
	}
	applySourceReadiness(&view)
	return view
}

func applySourceReadiness(view *openSourcePolicyView) {
	if !view.DBIndexReady {
		view.CanMigrate = false
		view.MigrationBlockReason = "검증된 Rule·Setup DB 인덱스가 준비되지 않았습니다."
	} else if !view.PackagesReady() {
		view.CanMigrate = false
		view.MigrationBlockReason = "policy-bundle-v3 또는 호환 Agent·모듈 패키지가 필요합니다."
	} else {
		return
	}
	if view.LinkStatus == "AVAILABLE" {
		view.Status, view.LinkStatus = "BLOCKED", "BLOCKED"
	}
}

func exactSourceMatchesSystemPolicy(source model.PolicySourceArtifact, current systempolicy.Template) bool {
	ref := current.Defaults.CRSSource
	return ref != nil && ref.ID == source.ID && strings.EqualFold(ref.ArchiveSHA256, source.ArchiveSHA256) && strings.EqualFold(ref.IndexSHA256, source.IndexSHA256)
}

func sourceMatchesSystemPolicy(source model.PolicySourceArtifact, current systempolicy.Template) bool {
	return exactSourceMatchesSystemPolicy(source, current)
}

func (s *Server) openSourceLifecycle(r *http.Request, items []openSourcePolicyView) openSourcePolicyLifecycle {
	view := openSourcePolicyLifecycle{HasSources: len(s.allPolicySources()) != 0}
	current := s.defaultSystemPolicyTemplate(r.Context())
	if current.Key != "" {
		view.HasCurrent = true
		view.CurrentPolicyVersion = current.Version
		view.CurrentPolicyReference = current.Reference()
		view.CurrentCRSVersion = current.CRSVersion
		view.CurrentCRSChannel = current.CRSTrack
		if current.Defaults.CRSSource != nil {
			view.CurrentSourceID = current.Defaults.CRSSource.ID
		}
		view.CurrentLinkStatus = "LEGACY_UNPINNED"
	}
	allSources := append([]model.PolicySourceArtifact(nil), s.allPolicySources()...)
	sort.SliceStable(allSources, func(i, j int) bool { return newerCRSVersion(allSources[i].Version, allSources[j].Version) })
	for _, source := range allSources {
		_, sourceIndex, ok, err := s.indexedPolicySource(r.Context(), source.ID)
		if err != nil || !ok {
			continue
		}
		item, err := s.openSourcePolicyView(r, source, sourceIndex)
		if err != nil {
			continue
		}
		item = classifyOpenSourcePolicyView(item, current)
		if view.LatestSourceID == "" {
			view.LatestSourceID, view.LatestSourceVersion, view.LatestSourceTag = source.ID, source.Version, source.Tag
			view.LatestPackagesReady = item.PackagesReady()
		}
		if item.LinkStatus == "CURRENT" || item.LinkStatus == "LEGACY_UNPINNED" {
			view.CurrentLinkStatus = item.LinkStatus
		}
		if item.CanMigrate && view.HasCurrent {
			view.HasNewSource = true
		}
	}
	view.LastCheckedAt = s.lastCRSSourceSyncAt().Local()
	return view
}

func newerCRSVersion(left, right string) bool {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
		if len(parts) != len(result) {
			return result, false
		}
		for index, part := range parts {
			number, err := strconv.Atoi(part)
			if err != nil || number < 0 {
				return result, false
			}
			result[index] = number
		}
		return result, true
	}
	leftParts, leftOK := parse(left)
	rightParts, rightOK := parse(right)
	if !leftOK || !rightOK {
		return left > right
	}
	for index := range leftParts {
		if leftParts[index] != rightParts[index] {
			return leftParts[index] > rightParts[index]
		}
	}
	return false
}

func (s *Server) openSourcePolicyView(r *http.Request, source model.PolicySourceArtifact, index crsindex.Index) (openSourcePolicyView, error) {
	view := openSourcePolicyView{Source: source, Statistics: index.Statistics, SetupCount: len(index.Setup), Status: "AVAILABLE"}
	status, indexed, err := s.store.CRSReleaseIndexStatus(r.Context(), source.ID)
	if err != nil {
		return view, err
	}
	view.ReleaseStatus, view.DBIndexReady = status, indexed
	verifiedAt, err := s.store.CRSReleaseVerifiedAt(r.Context(), source.ID)
	if err != nil {
		return view, err
	}
	view.VerifiedAt = verifiedAt
	versions, err := s.store.ListSystemPolicyVersions(r.Context())
	if err != nil {
		return view, err
	}
	for _, version := range versions {
		matches := version.Defaults.CRSSource != nil && version.Defaults.CRSSource.ID == source.ID && strings.EqualFold(version.Defaults.CRSSource.ArchiveSHA256, source.ArchiveSHA256) && strings.EqualFold(version.Defaults.CRSSource.IndexSHA256, source.IndexSHA256)
		if !matches {
			continue
		}
		view.SystemPolicyCount++
		view.EnterpriseCount += version.EnterpriseCount
		if view.LinkedSystemPolicyID == "" {
			view.LinkedSystemPolicyID, view.LinkedSystemPolicyVersion = version.ID, version.Version
		}
	}
	for _, packageID := range source.CompatiblePackageIDs {
		if s.catalog == nil {
			break
		}
		artifact, ok := s.catalog.Artifact(packageID)
		if !ok {
			continue
		}
		switch artifact.Kind {
		case "agent":
			view.AgentPackageCount++
		case "module":
			view.ModulePackageCount++
		}
	}
	return view, nil
}

func (s *Server) policySource(sourceID string) (model.PolicySourceArtifact, crsindex.Index, bool) {
	if source, index, ok := s.runtimePolicySource(sourceID); ok {
		return source, index, true
	}
	if s.catalog == nil {
		return model.PolicySourceArtifact{}, crsindex.Index{}, false
	}
	return s.catalog.PolicySource(strings.TrimSpace(sourceID))
}

func (s *Server) indexedPolicySource(ctx context.Context, sourceID string) (model.PolicySourceArtifact, crsindex.Index, bool, error) {
	source, _, ok := s.policySource(sourceID)
	if !ok {
		return model.PolicySourceArtifact{}, crsindex.Index{}, false, nil
	}
	index, err := s.store.CRSReleaseIndex(ctx, source.ID)
	if err != nil {
		return model.PolicySourceArtifact{}, crsindex.Index{}, true, err
	}
	return source, index, true, nil
}

func (s *Server) openSourcePolicyDetailData(r *http.Request) (openSourcePolicyDetail, bool, error) {
	source, index, ok, err := s.indexedPolicySource(r.Context(), r.PathValue("source_id"))
	if err != nil {
		return openSourcePolicyDetail{}, true, err
	}
	if !ok {
		return openSourcePolicyDetail{}, false, nil
	}
	view, err := s.openSourcePolicyView(r, source, index)
	if err != nil {
		return openSourcePolicyDetail{}, true, err
	}
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	if page < 1 {
		page = 1
	}
	filters := map[string]string{
		"q": strings.ToLower(strings.TrimSpace(query.Get("q"))), "rule_id": strings.TrimSpace(query.Get("rule_id")),
		"file": strings.ToLower(strings.TrimSpace(query.Get("file"))), "tag": strings.ToLower(strings.TrimSpace(query.Get("tag"))),
		"severity": strings.ToLower(strings.TrimSpace(query.Get("severity"))), "phase": strings.TrimSpace(query.Get("phase")),
		"paranoia_level": strings.TrimSpace(query.Get("paranoia_level")),
	}
	matched := make([]openSourceRuleView, 0)
	for _, rule := range index.Rules {
		if !matchesSourceRule(rule, filters) {
			continue
		}
		matched = append(matched, openSourceRuleView{Rule: rule, GitHubURL: fixedGitHubRuleURL(source.Repository, source.Commit, rule.File, rule.Line)})
	}
	start := (page - 1) * openSourceRulePageSize
	if start > len(matched) {
		start = len(matched)
	}
	end := start + openSourceRulePageSize
	if end > len(matched) {
		end = len(matched)
	}
	detail := openSourcePolicyDetail{
		Policy: view, Setup: index.Setup, Rules: matched[start:end], Page: page, PageSize: openSourceRulePageSize,
		Total: len(matched), HasNext: end < len(matched), FilterQ: query.Get("q"), FilterID: query.Get("rule_id"),
		FilterFile: query.Get("file"), FilterTag: query.Get("tag"), FilterSeverity: query.Get("severity"),
		FilterPhase: query.Get("phase"), FilterPL: query.Get("paranoia_level"),
	}
	return detail, true, nil
}

func matchesSourceRule(rule crsindex.Rule, filters map[string]string) bool {
	if filters["rule_id"] != "" && strconv.Itoa(rule.ID) != filters["rule_id"] {
		return false
	}
	if filters["file"] != "" && !strings.Contains(strings.ToLower(rule.File), filters["file"]) {
		return false
	}
	if filters["severity"] != "" && strings.ToLower(rule.Severity) != filters["severity"] {
		return false
	}
	if filters["phase"] != "" && rule.Phase != filters["phase"] {
		return false
	}
	if filters["paranoia_level"] != "" && strconv.Itoa(rule.ParanoiaLevel) != filters["paranoia_level"] {
		return false
	}
	tags := strings.ToLower(strings.Join(rule.Tags, " "))
	if filters["tag"] != "" && !strings.Contains(tags, filters["tag"]) {
		return false
	}
	if filters["q"] != "" {
		haystack := strings.ToLower(fmt.Sprintf("%d %s %s %s %s", rule.ID, rule.File, rule.Message, rule.Operator, tags))
		if !strings.Contains(haystack, filters["q"]) {
			return false
		}
	}
	return true
}

func fixedGitHubRuleURL(repository, commit, file string, line int) string {
	parts := strings.Split(file, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.TrimSuffix(repository, "/") + "/blob/" + url.PathEscape(commit) + "/" + strings.Join(parts, "/") + "#L" + strconv.Itoa(line)
}

func (s *Server) openSourceDiff(r *http.Request, sourceID, baseID string) (openSourcePolicyDiff, bool, error) {
	_, candidate, ok, err := s.indexedPolicySource(r.Context(), sourceID)
	if err != nil {
		return openSourcePolicyDiff{}, true, err
	}
	if !ok {
		return openSourcePolicyDiff{}, false, nil
	}
	if baseID == "" {
		diff := openSourcePolicyDiff{SourceID: sourceID}
		diff.Rules.Added = append(diff.Rules.Added, candidate.Rules...)
		diff.Setup = compareSourceSetup(nil, candidate.Setup)
		return diff, true, nil
	}
	base, ok := s.systemPolicyTemplate(r.Context(), baseID)
	if !ok {
		return openSourcePolicyDiff{}, true, fmt.Errorf("base system policy not found")
	}
	var previous crsindex.Index
	if base.Defaults.CRSSource != nil {
		_, previous, _, err = s.indexedPolicySource(r.Context(), base.Defaults.CRSSource.ID)
		if err != nil {
			return openSourcePolicyDiff{}, true, err
		}
	} else {
		for _, source := range s.allPolicySources() {
			if strings.TrimPrefix(source.Version, "v") == strings.TrimPrefix(base.CRSVersion, "v") {
				_, previous, _, err = s.indexedPolicySource(r.Context(), source.ID)
				if err != nil {
					return openSourcePolicyDiff{}, true, err
				}
				break
			}
		}
	}
	diff := openSourcePolicyDiff{SourceID: sourceID, BaseSystemPolicyID: baseID}
	previousRules := make(map[int]crsindex.Rule, len(previous.Rules))
	for _, rule := range previous.Rules {
		previousRules[rule.ID] = rule
	}
	for _, rule := range candidate.Rules {
		old, exists := previousRules[rule.ID]
		if !exists {
			diff.Rules.Added = append(diff.Rules.Added, rule)
		} else if old.ContentHash != rule.ContentHash {
			diff.Rules.Changed = append(diff.Rules.Changed, rule)
		}
		delete(previousRules, rule.ID)
	}
	for _, rule := range previousRules {
		diff.Rules.Removed = append(diff.Rules.Removed, rule)
	}
	sort.Slice(diff.Rules.Removed, func(i, j int) bool { return diff.Rules.Removed[i].ID < diff.Rules.Removed[j].ID })
	diff.Setup = compareSourceSetup(previous.Setup, candidate.Setup)
	return diff, true, nil
}

func compareSourceSetup(previous, next []crsindex.SetupField) []sourceSetupDiff {
	old := make(map[string]crsindex.SetupField, len(previous))
	for _, field := range previous {
		old[field.Key] = field
	}
	changes := make([]sourceSetupDiff, 0)
	for _, field := range next {
		prior, exists := old[field.Key]
		switch {
		case !exists:
			changes = append(changes, sourceSetupDiff{Key: field.Key, Change: "ADDED", Next: field.Type})
		case prior.Type != field.Type:
			changes = append(changes, sourceSetupDiff{Key: field.Key, Change: "TYPE_CHANGED", Previous: prior.Type, Next: field.Type})
		case !sameSourceSetupSchema(prior, field):
			changes = append(changes, sourceSetupDiff{Key: field.Key, Change: "SCHEMA_CHANGED", Previous: sourceSetupSchemaSummary(prior), Next: sourceSetupSchemaSummary(field)})
		}
		delete(old, field.Key)
	}
	for key, field := range old {
		changes = append(changes, sourceSetupDiff{Key: key, Change: "REMOVED", Previous: field.Type})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes
}

func sameSourceSetupSchema(left, right crsindex.SetupField) bool {
	if left.Type != right.Type || left.Default != right.Default || left.Minimum != right.Minimum || left.Maximum != right.Maximum || len(left.Options) != len(right.Options) {
		return false
	}
	for index := range left.Options {
		if left.Options[index] != right.Options[index] {
			return false
		}
	}
	return true
}

func sourceSetupSchemaSummary(field crsindex.SetupField) string {
	return fmt.Sprintf("%s default=%s range=%d..%d options=%s", field.Type, field.Default, field.Minimum, field.Maximum, strings.Join(field.Options, ","))
}
