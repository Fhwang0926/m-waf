package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const (
	PolicyConfigStorageLegacy     = 1
	PolicyConfigStorageStructured = 2

	PolicyConfigPending      = "PENDING"
	PolicyConfigMigrated     = "MIGRATED"
	PolicyConfigLegacyCompat = "LEGACY_COMPAT"
	PolicyConfigLegacyLocked = "LEGACY_LOCKED"
	PolicyConfigFailed       = "FAILED"

	PolicyScopeSystem     = "SYSTEM"
	PolicyScopeEnterprise = "ENTERPRISE"

	PolicyExclusionRule         = "RULE"
	PolicyExclusionTarget       = "TARGET"
	PolicyExclusionTag          = "TAG"
	PolicyExclusionEngineBypass = "ENGINE_BYPASS"

	PolicyExclusionBefore = "BEFORE_CRS"
	PolicyExclusionAfter  = "AFTER_CRS"

	PolicyIPActionBlock = "BLOCK"
	PolicyIPActionTrust = "TRUST"
)

const (
	CRSReleaseVerified  = "VERIFIED"
	CRSReleaseRejected  = "REJECTED"
	CRSReleaseWithdrawn = "WITHDRAWN"

	PolicyMigrationSafe     = "SAFE"
	PolicyMigrationRequired = "MIGRATION_REQUIRED"
)

const (
	mwafSetupRuleIDMin     = 1000
	mwafSetupRuleIDMax     = 4999
	mwafGeneratedRuleIDMin = 5000
	mwafGeneratedRuleIDMax = 9999
	systemRuleIDMin        = 10000
	systemRuleIDMax        = 39999
	enterpriseRuleIDMin    = 40000
	enterpriseRuleIDMax    = 89999
)

type PolicyMigrationRequiredError struct{ Detail string }

func (e PolicyMigrationRequiredError) Error() string { return e.Detail }

func migrationRequiredf(format string, args ...any) error {
	return PolicyMigrationRequiredError{Detail: fmt.Sprintf(format, args...)}
}

// CRSRelease is the immutable database identity of one verified upstream
// archive and its searchable index. The original files remain in artifact
// storage and are never reconstructed from these fields.
type CRSRelease struct {
	ID                   string    `json:"id"`
	Provider             string    `json:"provider"`
	Repository           string    `json:"repository"`
	Channel              string    `json:"channel"`
	Version              string    `json:"version"`
	Tag                  string    `json:"tag"`
	CommitSHA            string    `json:"commit_sha"`
	TagObjectSHA         string    `json:"tag_object_sha"`
	TagSignatureVerified bool      `json:"tag_signature_verified"`
	ArchivePath          string    `json:"archive_path"`
	ArchiveSize          int64     `json:"archive_size"`
	ArchiveSHA256        string    `json:"archive_sha256"`
	IndexPath            string    `json:"index_path"`
	IndexSize            int64     `json:"index_size"`
	IndexSHA256          string    `json:"index_sha256"`
	Status               string    `json:"status"`
	VerifiedAt           time.Time `json:"verified_at,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

type PolicyMigrationImpact struct {
	EnterprisePolicyID          string    `json:"enterprise_policy_id"`
	TargetSystemPolicyVersionID string    `json:"target_system_policy_version_id"`
	Status                      string    `json:"status"`
	Detail                      string    `json:"detail,omitempty"`
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
}

type CRSSetupValue struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	SourceScope string `json:"source_scope"`
}

type PolicyExclusionCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Order    int    `json:"order"`
}

type PolicyExclusion struct {
	ID              string                     `json:"id,omitempty"`
	SourceScope     string                     `json:"source_scope"`
	Type            string                     `json:"type"`
	LoadStage       string                     `json:"load_stage"`
	RuleID          int                        `json:"rule_id,omitempty"`
	RuleTag         string                     `json:"rule_tag,omitempty"`
	Target          string                     `json:"target,omitempty"`
	GeneratedRuleID int                        `json:"generated_rule_id,omitempty"`
	Reason          string                     `json:"reason,omitempty"`
	ExpiresAt       *time.Time                 `json:"expires_at,omitempty"`
	Enabled         bool                       `json:"enabled"`
	Legacy          bool                       `json:"legacy"`
	Order           int                        `json:"order"`
	Conditions      []PolicyExclusionCondition `json:"conditions,omitempty"`
}

type PolicyCustomRule struct {
	ID               string `json:"id,omitempty"`
	SourceScope      string `json:"source_scope"`
	RuleID           int    `json:"rule_id"`
	Name             string `json:"name,omitempty"`
	Phase            string `json:"phase"`
	Severity         string `json:"severity,omitempty"`
	CanonicalSecRule string `json:"canonical_sec_rule"`
	ContentSHA256    string `json:"content_sha256"`
	Enabled          bool   `json:"enabled"`
	LegacyIDRange    bool   `json:"legacy_id_range"`
	Order            int    `json:"order"`
}

type PolicyIPRule struct {
	ID              string     `json:"id,omitempty"`
	SourceScope     string     `json:"source_scope"`
	Action          string     `json:"action"`
	Network         string     `json:"network"`
	GeneratedRuleID int        `json:"generated_rule_id"`
	Reason          string     `json:"reason"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedBy       string     `json:"created_by,omitempty"`
	Enabled         bool       `json:"enabled"`
	Order           int        `json:"order"`
}

// PolicyConfiguration is the authoritative, immutable policy authoring model.
// Exactly one owner is set. Policy revision configurations contain the fully
// resolved system and enterprise settings used to reproduce the signed bundle.
type PolicyConfiguration struct {
	ID                       string             `json:"id,omitempty"`
	SystemPolicyVersionID    string             `json:"system_policy_version_id,omitempty"`
	PolicyRevisionID         string             `json:"policy_revision_id,omitempty"`
	CRSReleaseID             string             `json:"crs_release_id,omitempty"`
	EngineMode               string             `json:"engine_mode"`
	BlockingParanoiaLevel    int                `json:"blocking_paranoia_level"`
	ExecutingParanoiaLevel   int                `json:"executing_paranoia_level"`
	InboundAnomalyThreshold  int                `json:"inbound_anomaly_threshold"`
	OutboundAnomalyThreshold int                `json:"outbound_anomaly_threshold"`
	RequestBodyAccess        bool               `json:"request_body_access"`
	ResponseBodyAccess       bool               `json:"response_body_access"`
	EarlyBlocking            bool               `json:"early_blocking"`
	SamplingPercentage       int                `json:"sampling_percentage"`
	RuleIDNamespaceVersion   int                `json:"rule_id_namespace_version"`
	ConfigSHA256             string             `json:"config_sha256,omitempty"`
	Setup                    []CRSSetupValue    `json:"setup,omitempty"`
	Exclusions               []PolicyExclusion  `json:"exclusions,omitempty"`
	CustomRules              []PolicyCustomRule `json:"custom_rules,omitempty"`
	IPRules                  []PolicyIPRule     `json:"ip_rules,omitempty"`
}

func (c *PolicyConfiguration) Normalize() {
	if c.ExecutingParanoiaLevel == 0 {
		c.ExecutingParanoiaLevel = c.BlockingParanoiaLevel
	}
	if c.OutboundAnomalyThreshold == 0 {
		c.OutboundAnomalyThreshold = 4
	}
	if c.SamplingPercentage == 0 {
		c.SamplingPercentage = 100
	}
	if c.RuleIDNamespaceVersion == 0 {
		c.RuleIDNamespaceVersion = 1
	}
	for index := range c.Setup {
		c.Setup[index].Key = strings.TrimSpace(c.Setup[index].Key)
		c.Setup[index].Value = strings.Join(strings.Fields(c.Setup[index].Value), " ")
	}
	for index := range c.Exclusions {
		item := &c.Exclusions[index]
		item.RuleTag = strings.TrimSpace(item.RuleTag)
		item.Target = strings.TrimSpace(item.Target)
		item.Reason = strings.TrimSpace(item.Reason)
		for conditionIndex := range item.Conditions {
			condition := &item.Conditions[conditionIndex]
			condition.Field = strings.TrimSpace(condition.Field)
			condition.Operator = strings.TrimSpace(condition.Operator)
			condition.Value = strings.TrimSpace(condition.Value)
			condition.Order = conditionIndex
		}
		sort.SliceStable(item.Conditions, func(i, j int) bool { return item.Conditions[i].Order < item.Conditions[j].Order })
	}
	for index := range c.CustomRules {
		item := &c.CustomRules[index]
		item.Name = strings.TrimSpace(item.Name)
		item.Phase = strings.TrimSpace(item.Phase)
		item.Severity = strings.TrimSpace(item.Severity)
		item.CanonicalSecRule = strings.TrimSpace(strings.ReplaceAll(item.CanonicalSecRule, "\r\n", "\n"))
		digest := sha256.Sum256([]byte(item.CanonicalSecRule))
		item.ContentSHA256 = hex.EncodeToString(digest[:])
	}
	for index := range c.IPRules {
		item := &c.IPRules[index]
		item.Network, _ = canonicalPolicyNetwork(item.Network)
		item.Reason = strings.TrimSpace(item.Reason)
		item.CreatedBy = strings.TrimSpace(item.CreatedBy)
	}
	sort.SliceStable(c.Setup, func(i, j int) bool { return c.Setup[i].Key < c.Setup[j].Key })
	sort.SliceStable(c.Exclusions, func(i, j int) bool { return c.Exclusions[i].Order < c.Exclusions[j].Order })
	sort.SliceStable(c.CustomRules, func(i, j int) bool { return c.CustomRules[i].Order < c.CustomRules[j].Order })
	sort.SliceStable(c.IPRules, func(i, j int) bool { return c.IPRules[i].Order < c.IPRules[j].Order })
}

func (c PolicyConfiguration) ValidateAt(now time.Time) error {
	if (c.SystemPolicyVersionID == "") == (c.PolicyRevisionID == "") {
		return errors.New("policy configuration requires exactly one owner")
	}
	if c.EngineMode != "DetectionOnly" && c.EngineMode != "On" {
		return errors.New("policy engine mode must be DetectionOnly or On")
	}
	if c.BlockingParanoiaLevel < 1 || c.BlockingParanoiaLevel > 4 || c.ExecutingParanoiaLevel < c.BlockingParanoiaLevel || c.ExecutingParanoiaLevel > 4 {
		return errors.New("executing paranoia level must be between blocking paranoia level and 4")
	}
	if c.InboundAnomalyThreshold < 1 || c.InboundAnomalyThreshold > 100 || c.OutboundAnomalyThreshold < 1 || c.OutboundAnomalyThreshold > 100 {
		return errors.New("anomaly thresholds must be between 1 and 100")
	}
	if c.SamplingPercentage < 1 || c.SamplingPercentage > 100 {
		return errors.New("sampling percentage must be between 1 and 100")
	}
	if c.RuleIDNamespaceVersion != 1 {
		return errors.New("unsupported policy rule ID namespace")
	}
	setupKeys := make(map[string]bool)
	for _, item := range c.Setup {
		if item.Key == "" || item.Value == "" || !validPolicyScope(item.SourceScope) || setupKeys[item.Key] {
			return fmt.Errorf("invalid or duplicate CRS setup value %q", item.Key)
		}
		setupKeys[item.Key] = true
	}
	usedIDs := make(map[int]bool)
	for _, item := range c.Exclusions {
		if err := validatePolicyExclusion(item, now); err != nil {
			return err
		}
		if item.GeneratedRuleID != 0 {
			if item.GeneratedRuleID < mwafGeneratedRuleIDMin || item.GeneratedRuleID > mwafGeneratedRuleIDMax || usedIDs[item.GeneratedRuleID] {
				return fmt.Errorf("generated rule ID %d is outside the M-WAF namespace or duplicated", item.GeneratedRuleID)
			}
			usedIDs[item.GeneratedRuleID] = true
		}
	}
	seenIPRules := make(map[string]bool)
	for _, item := range c.IPRules {
		if !validPolicyScope(item.SourceScope) || (item.Action != PolicyIPActionBlock && item.Action != PolicyIPActionTrust) {
			return errors.New("IP Rule requires a valid scope and action")
		}
		canonical, err := canonicalPolicyNetwork(item.Network)
		if err != nil || canonical != item.Network {
			return fmt.Errorf("IP Rule network %q is not canonical", item.Network)
		}
		key := item.Action + "\x00" + item.Network
		if seenIPRules[key] {
			return fmt.Errorf("duplicate IP Rule %s %s", item.Action, item.Network)
		}
		seenIPRules[key] = true
		if item.Reason == "" {
			return errors.New("IP Rule requires a reason")
		}
		if item.Action == PolicyIPActionTrust {
			if item.ExpiresAt == nil || !item.ExpiresAt.After(now) || item.ExpiresAt.After(now.Add(7*24*time.Hour)) {
				return errors.New("trusted IP expiry must be within seven days")
			}
		} else if item.ExpiresAt != nil && !item.ExpiresAt.After(now) {
			return errors.New("IP block expiry must be in the future")
		}
		if item.GeneratedRuleID < mwafGeneratedRuleIDMin || item.GeneratedRuleID > mwafGeneratedRuleIDMax || usedIDs[item.GeneratedRuleID] {
			return fmt.Errorf("generated IP Rule ID %d is outside the M-WAF namespace or duplicated", item.GeneratedRuleID)
		}
		usedIDs[item.GeneratedRuleID] = true
	}
	for _, item := range c.CustomRules {
		if !validPolicyScope(item.SourceScope) || item.RuleID == 0 || item.CanonicalSecRule == "" {
			return errors.New("custom Rule requires scope, ID and SecRule text")
		}
		validated, count, err := safeCustomRules(item.CanonicalSecRule)
		if err != nil || count != 1 || strings.TrimSpace(validated) != strings.TrimSpace(item.CanonicalSecRule) {
			return fmt.Errorf("custom Rule %d is not a canonical safe single SecRule", item.RuleID)
		}
		match := customRuleID.FindStringSubmatch(item.CanonicalSecRule)
		if len(match) != 2 {
			return fmt.Errorf("custom Rule %d text has no ID", item.RuleID)
		}
		parsedID, _ := strconv.Atoi(match[1])
		if parsedID != item.RuleID {
			return fmt.Errorf("custom Rule %d text contains a different ID", item.RuleID)
		}
		validRange := item.SourceScope == PolicyScopeSystem && item.RuleID >= systemRuleIDMin && item.RuleID <= systemRuleIDMax ||
			item.SourceScope == PolicyScopeEnterprise && item.RuleID >= enterpriseRuleIDMin && item.RuleID <= enterpriseRuleIDMax
		if !item.LegacyIDRange && !validRange {
			return fmt.Errorf("custom Rule ID %d is outside the %s namespace", item.RuleID, item.SourceScope)
		}
		if item.LegacyIDRange && !isLegacyPolicyRuleID(item.RuleID) {
			return fmt.Errorf("legacy custom Rule ID %d is outside a preserved legacy namespace", item.RuleID)
		}
		if usedIDs[item.RuleID] {
			return fmt.Errorf("duplicate policy Rule ID %d", item.RuleID)
		}
		usedIDs[item.RuleID] = true
	}
	return nil
}

func isLegacyPolicyRuleID(id int) bool {
	return id >= 100000 && id <= 199999 || id >= 240000 && id <= 249999
}

func sameCRSMajorMinor(left, right string) bool {
	leftParts := strings.Split(strings.TrimPrefix(strings.TrimSpace(left), "v"), ".")
	rightParts := strings.Split(strings.TrimPrefix(strings.TrimSpace(right), "v"), ".")
	return len(leftParts) >= 2 && len(rightParts) >= 2 && leftParts[0] == rightParts[0] && leftParts[1] == rightParts[1]
}

func validatePolicyExclusion(item PolicyExclusion, now time.Time) error {
	if !validPolicyScope(item.SourceScope) || (item.LoadStage != PolicyExclusionBefore && item.LoadStage != PolicyExclusionAfter) {
		return errors.New("policy exclusion requires a valid scope and load stage")
	}
	if item.LoadStage == PolicyExclusionBefore && len(item.Conditions) == 0 {
		return errors.New("runtime exclusion requires a condition before CRS")
	}
	if item.LoadStage == PolicyExclusionAfter && len(item.Conditions) != 0 {
		return errors.New("configure-time exclusion cannot contain runtime conditions")
	}
	if item.LoadStage == PolicyExclusionAfter && item.GeneratedRuleID != 0 {
		return errors.New("configure-time exclusion cannot reserve a generated Rule ID")
	}
	switch item.Type {
	case PolicyExclusionRule:
		if item.RuleID == 0 {
			return errors.New("Rule exclusion requires a Rule ID")
		}
	case PolicyExclusionTarget:
		if item.RuleID == 0 || item.Target == "" || strings.ContainsAny(item.Target, "\"'\\;\r\n \t") {
			return errors.New("target exclusion requires a Rule ID and target")
		}
	case PolicyExclusionTag:
		if item.RuleTag == "" || strings.ContainsAny(item.RuleTag, "\"'\\\r\n \t") {
			return errors.New("tag exclusion requires a tag")
		}
	case PolicyExclusionEngineBypass:
		if item.LoadStage != PolicyExclusionBefore || item.GeneratedRuleID == 0 {
			return errors.New("engine bypass requires a condition and generated Rule ID")
		}
		if !item.Legacy {
			if item.Reason == "" || item.ExpiresAt == nil {
				return errors.New("new engine bypass requires a reason and expiry")
			}
			if item.ExpiresAt.Before(now) || item.ExpiresAt.After(now.Add(7*24*time.Hour)) {
				return errors.New("engine bypass expiry must be within seven days")
			}
		}
	default:
		return errors.New("unsupported policy exclusion type")
	}
	for _, condition := range item.Conditions {
		if !validConditionField(condition.Field) || !validConditionOperator(condition.Operator) || condition.Value == "" || len(condition.Value) > 1024 || strings.ContainsAny(condition.Value, "\"\\\r\n") {
			return errors.New("policy exclusion contains an unsupported condition")
		}
		if condition.Operator == "@ipMatch" && condition.Field != "REMOTE_ADDR" {
			return errors.New("@ipMatch is only allowed for REMOTE_ADDR")
		}
		if condition.Operator == "@ipMatch" && !validIPMatchValue(condition.Value) {
			return errors.New("@ipMatch requires valid IP or CIDR values")
		}
	}
	if item.LoadStage == PolicyExclusionBefore && item.GeneratedRuleID == 0 {
		return errors.New("conditional exclusion requires a generated Rule ID")
	}
	return nil
}

func validIPMatchValue(value string) bool {
	items := strings.FieldsFunc(value, func(char rune) bool { return char == ',' || char == ' ' || char == '\t' })
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		if net.ParseIP(item) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(item); err != nil {
			return false
		}
	}
	return true
}

func canonicalPolicyNetwork(value string) (string, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address.Unmap(), bits).Masked().String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", errors.New("valid IP address or CIDR is required")
	}
	return prefix.Masked().String(), nil
}

func validPolicyScope(value string) bool {
	return value == PolicyScopeSystem || value == PolicyScopeEnterprise
}

func validConditionField(value string) bool {
	switch value {
	case "REQUEST_URI", "REQUEST_METHOD", "REQUEST_HEADERS:Host", "REMOTE_ADDR":
		return true
	default:
		return false
	}
}

func validConditionOperator(value string) bool {
	return value == "@beginsWith" || value == "@streq" || value == "@ipMatch"
}

func (c *PolicyConfiguration) UpdateDigest() error {
	c.Normalize()
	copyValue := *c
	copyValue.ID = ""
	copyValue.SystemPolicyVersionID = ""
	copyValue.PolicyRevisionID = ""
	copyValue.ConfigSHA256 = ""
	for index := range copyValue.Exclusions {
		copyValue.Exclusions[index].ID = ""
	}
	for index := range copyValue.CustomRules {
		copyValue.CustomRules[index].ID = ""
	}
	for index := range copyValue.IPRules {
		copyValue.IPRules[index].ID = ""
	}
	raw, err := json.Marshal(copyValue)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	c.ConfigSHA256 = hex.EncodeToString(digest[:])
	return nil
}

func (c PolicyConfiguration) CRSSetupMap() map[string]string {
	values := make(map[string]string, len(c.Setup)+6)
	for _, item := range c.Setup {
		values[item.Key] = item.Value
	}
	values["blocking_paranoia_level"] = strconv.Itoa(c.BlockingParanoiaLevel)
	values["detection_paranoia_level"] = strconv.Itoa(c.ExecutingParanoiaLevel)
	values["inbound_anomaly_score_threshold"] = strconv.Itoa(c.InboundAnomalyThreshold)
	values["outbound_anomaly_score_threshold"] = strconv.Itoa(c.OutboundAnomalyThreshold)
	values["early_blocking"] = boolInt(c.EarlyBlocking)
	values["sampling_percentage"] = strconv.Itoa(c.SamplingPercentage)
	return values
}

// ApplyToSettings preserves legacy metadata while replacing every effective
// authoring value with the structured snapshot. System-scope overlays remain
// in the snapshot and are not duplicated into enterprise edit fields.
func (c PolicyConfiguration) ApplyToSettings(settings PolicySettings) PolicySettings {
	settings.ParanoiaLevel = c.BlockingParanoiaLevel
	settings.ExecutingParanoiaLevel = c.ExecutingParanoiaLevel
	settings.InboundScore = c.InboundAnomalyThreshold
	settings.OutboundScore = c.OutboundAnomalyThreshold
	settings.RequestBody = c.RequestBodyAccess
	settings.ResponseBody = c.ResponseBodyAccess
	settings.EarlyBlocking = c.EarlyBlocking
	settings.SamplingPercentage = c.SamplingPercentage
	settings.ExcludedPaths = nil
	settings.ExcludedIPs = nil
	settings.Exclusions = nil
	settings.CustomRules = ""
	settings.CustomRuleCount = 0
	for _, item := range c.Exclusions {
		if item.SourceScope != PolicyScopeEnterprise {
			continue
		}
		if item.Type == PolicyExclusionEngineBypass && item.Legacy && len(item.Conditions) == 1 {
			condition := item.Conditions[0]
			switch {
			case condition.Field == "REQUEST_URI" && condition.Operator == "@beginsWith":
				settings.ExcludedPaths = append(settings.ExcludedPaths, condition.Value)
			case condition.Field == "REMOTE_ADDR" && condition.Operator == "@ipMatch":
				settings.ExcludedIPs = append(settings.ExcludedIPs, condition.Value)
			default:
				settings.Exclusions = append(settings.Exclusions, item)
			}
			continue
		}
		settings.Exclusions = append(settings.Exclusions, item)
	}
	var customRules []string
	for _, item := range c.CustomRules {
		if item.SourceScope == PolicyScopeEnterprise && item.Enabled {
			customRules = append(customRules, item.CanonicalSecRule)
		}
	}
	settings.CustomRules = strings.Join(customRules, "\n")
	settings.CustomRuleCount = len(customRules)
	return settings
}

func (c PolicyConfiguration) ScopeCounts(scope string) (setup, exclusions, customRules int) {
	for _, item := range c.Setup {
		if item.SourceScope == scope {
			setup++
		}
	}
	for _, item := range c.Exclusions {
		if item.SourceScope == scope && item.Enabled {
			exclusions++
		}
	}
	for _, item := range c.CustomRules {
		if item.SourceScope == scope && item.Enabled {
			customRules++
		}
	}
	for _, item := range c.IPRules {
		if item.SourceScope == scope && item.Enabled {
			customRules++
		}
	}
	return setup, exclusions, customRules
}

func (c PolicyConfiguration) SystemScopeLabel() string {
	setup, exclusions, customRules := c.ScopeCounts(PolicyScopeSystem)
	return fmt.Sprintf("Setup %d · 예외 %d · Rule %d", setup, exclusions, customRules)
}

func (c PolicyConfiguration) EnterpriseScopeLabel() string {
	_, exclusions, customRules := c.ScopeCounts(PolicyScopeEnterprise)
	return fmt.Sprintf("예외 %d · Rule %d", exclusions, customRules)
}

func (c PolicyConfiguration) EnterpriseEngineBypassCount() int {
	count := 0
	for _, item := range c.Exclusions {
		if item.SourceScope == PolicyScopeEnterprise && item.Type == PolicyExclusionEngineBypass && item.Enabled {
			count++
		}
	}
	return count
}

func (c PolicyConfiguration) ApplyToSystemPolicyTemplate(item systempolicy.Template) systempolicy.Template {
	item.Defaults.Mode = c.EngineMode
	item.Defaults.ParanoiaLevel = c.BlockingParanoiaLevel
	item.Defaults.ExecutingParanoiaLevel = c.ExecutingParanoiaLevel
	item.Defaults.InboundScore = c.InboundAnomalyThreshold
	item.Defaults.OutboundScore = c.OutboundAnomalyThreshold
	item.Defaults.RequestBody = c.RequestBodyAccess
	item.Defaults.ResponseBody = c.ResponseBodyAccess
	item.Defaults.EarlyBlocking = c.EarlyBlocking
	item.Defaults.SamplingPercentage = c.SamplingPercentage
	item.Defaults.CRSSetup = c.CRSSetupMap()
	item.Defaults.ExcludedPaths = nil
	item.Defaults.ExcludedIPs = nil
	item.Defaults.BeforeExclusions = nil
	item.Defaults.AfterExclusions = nil
	item.Defaults.TagExclusions = nil
	item.Defaults.TargetExclusions = nil
	item.Defaults.EngineBypasses = nil
	item.Defaults.CustomRules = ""
	item.Defaults.CustomRuleCount = 0
	for _, value := range c.Exclusions {
		if value.SourceScope != PolicyScopeSystem || !value.Enabled {
			continue
		}
		conditions := make([]systempolicy.RuleCondition, 0, len(value.Conditions))
		for _, condition := range value.Conditions {
			conditions = append(conditions, systempolicy.RuleCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value})
		}
		if value.Type == PolicyExclusionEngineBypass && value.Legacy && len(conditions) == 1 {
			switch {
			case conditions[0].Field == "REQUEST_URI" && conditions[0].Operator == "@beginsWith":
				item.Defaults.ExcludedPaths = append(item.Defaults.ExcludedPaths, conditions[0].Value)
			case conditions[0].Field == "REMOTE_ADDR" && conditions[0].Operator == "@ipMatch":
				item.Defaults.ExcludedIPs = append(item.Defaults.ExcludedIPs, conditions[0].Value)
			}
			continue
		}
		switch value.Type {
		case PolicyExclusionRule:
			exclusion := systempolicy.RuleExclusion{RuleID: value.RuleID, Conditions: conditions}
			if value.LoadStage == PolicyExclusionBefore {
				item.Defaults.BeforeExclusions = append(item.Defaults.BeforeExclusions, exclusion)
			} else {
				item.Defaults.AfterExclusions = append(item.Defaults.AfterExclusions, exclusion)
			}
		case PolicyExclusionTarget:
			item.Defaults.TargetExclusions = append(item.Defaults.TargetExclusions, systempolicy.TargetExclusion{RuleID: value.RuleID, Target: value.Target, Conditions: conditions})
		case PolicyExclusionTag:
			item.Defaults.TagExclusions = append(item.Defaults.TagExclusions, value.RuleTag)
		case PolicyExclusionEngineBypass:
			if value.ExpiresAt != nil {
				item.Defaults.EngineBypasses = append(item.Defaults.EngineBypasses, systempolicy.EngineBypass{Reason: value.Reason, ExpiresAt: *value.ExpiresAt, Conditions: conditions})
			}
		}
	}
	var rules []string
	for _, value := range c.CustomRules {
		if value.SourceScope == PolicyScopeSystem && value.Enabled {
			rules = append(rules, value.CanonicalSecRule)
		}
	}
	item.Defaults.CustomRules = strings.Join(rules, "\n")
	item.Defaults.CustomRuleCount = len(rules)
	return item
}

func boolInt(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func structuredConfigurationFromPolicy(ownerSystemPolicyID, ownerRevisionID string, template systempolicy.Template, mode string, settings PolicySettings) (PolicyConfiguration, bool, error) {
	configuration := PolicyConfiguration{
		ID: randomID(), SystemPolicyVersionID: ownerSystemPolicyID, PolicyRevisionID: ownerRevisionID, EngineMode: mode,
		BlockingParanoiaLevel: settings.ParanoiaLevel, ExecutingParanoiaLevel: settings.ExecutingParanoiaLevel,
		InboundAnomalyThreshold: settings.InboundScore, OutboundAnomalyThreshold: settings.OutboundScore,
		RequestBodyAccess: settings.RequestBody, ResponseBodyAccess: settings.ResponseBody, EarlyBlocking: settings.EarlyBlocking,
		SamplingPercentage: settings.SamplingPercentage, RuleIDNamespaceVersion: 1,
	}
	if template.Defaults.CRSSource != nil {
		configuration.CRSReleaseID = template.Defaults.CRSSource.ID
	}
	if configuration.BlockingParanoiaLevel == 0 {
		configuration.BlockingParanoiaLevel = template.Defaults.ParanoiaLevel
	}
	if configuration.ExecutingParanoiaLevel == 0 {
		configuration.ExecutingParanoiaLevel = configuration.BlockingParanoiaLevel
	}
	if configuration.InboundAnomalyThreshold == 0 {
		configuration.InboundAnomalyThreshold = template.Defaults.InboundScore
	}
	if configuration.OutboundAnomalyThreshold == 0 {
		configuration.OutboundAnomalyThreshold = 4
	}
	if configuration.SamplingPercentage == 0 {
		configuration.SamplingPercentage = 100
	}
	setupValues := make(map[string]CRSSetupValue)
	for key, value := range template.Defaults.CRSSetup {
		if isCorePolicySetupKey(key) {
			continue
		}
		setupValues[key] = CRSSetupValue{Key: key, Value: value, SourceScope: PolicyScopeSystem}
	}
	for _, value := range setupValues {
		configuration.Setup = append(configuration.Setup, value)
	}
	legacy := false
	generatedID := mwafGeneratedRuleIDMin
	appendBypass := func(scope, field, operator, value string) {
		configuration.Exclusions = append(configuration.Exclusions, PolicyExclusion{
			ID: randomID(), SourceScope: scope, Type: PolicyExclusionEngineBypass, LoadStage: PolicyExclusionBefore,
			GeneratedRuleID: generatedID, Enabled: true, Legacy: true, Order: len(configuration.Exclusions),
			Conditions: []PolicyExclusionCondition{{Field: field, Operator: operator, Value: value}},
		})
		generatedID++
		legacy = true
	}
	for _, value := range template.Defaults.ExcludedIPs {
		appendBypass(PolicyScopeSystem, "REMOTE_ADDR", "@ipMatch", value)
	}
	for _, value := range template.Defaults.ExcludedPaths {
		appendBypass(PolicyScopeSystem, "REQUEST_URI", "@beginsWith", value)
	}
	for _, item := range template.Defaults.EngineBypasses {
		exclusion := PolicyExclusion{
			ID: randomID(), SourceScope: PolicyScopeSystem, Type: PolicyExclusionEngineBypass, LoadStage: PolicyExclusionBefore,
			GeneratedRuleID: generatedID, Reason: item.Reason, ExpiresAt: &item.ExpiresAt, Enabled: true, Order: len(configuration.Exclusions),
		}
		generatedID++
		for index, condition := range item.Conditions {
			exclusion.Conditions = append(exclusion.Conditions, PolicyExclusionCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value, Order: index})
		}
		configuration.Exclusions = append(configuration.Exclusions, exclusion)
	}
	appendRuleExclusions := func(scope, stage string, items []systempolicy.RuleExclusion) {
		for _, item := range items {
			exclusion := PolicyExclusion{ID: randomID(), SourceScope: scope, Type: PolicyExclusionRule, LoadStage: stage, RuleID: item.RuleID, Enabled: true, Order: len(configuration.Exclusions)}
			if len(item.Conditions) != 0 {
				exclusion.GeneratedRuleID = generatedID
				generatedID++
			}
			for index, condition := range item.Conditions {
				exclusion.Conditions = append(exclusion.Conditions, PolicyExclusionCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value, Order: index})
			}
			configuration.Exclusions = append(configuration.Exclusions, exclusion)
		}
	}
	appendRuleExclusions(PolicyScopeSystem, PolicyExclusionBefore, template.Defaults.BeforeExclusions)
	appendRuleExclusions(PolicyScopeSystem, PolicyExclusionAfter, template.Defaults.AfterExclusions)
	for _, tag := range template.Defaults.TagExclusions {
		configuration.Exclusions = append(configuration.Exclusions, PolicyExclusion{
			ID: randomID(), SourceScope: PolicyScopeSystem, Type: PolicyExclusionTag, LoadStage: PolicyExclusionAfter,
			RuleTag: tag, Enabled: true, Order: len(configuration.Exclusions),
		})
	}
	for _, item := range template.Defaults.TargetExclusions {
		exclusion := PolicyExclusion{ID: randomID(), SourceScope: PolicyScopeSystem, Type: PolicyExclusionTarget, LoadStage: PolicyExclusionAfter, RuleID: item.RuleID, Target: item.Target, Enabled: true, Order: len(configuration.Exclusions)}
		if len(item.Conditions) != 0 {
			exclusion.LoadStage = PolicyExclusionBefore
			exclusion.GeneratedRuleID = generatedID
			generatedID++
			for index, condition := range item.Conditions {
				exclusion.Conditions = append(exclusion.Conditions, PolicyExclusionCondition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value, Order: index})
			}
		}
		configuration.Exclusions = append(configuration.Exclusions, exclusion)
	}
	// The system layer always owns the first generated-ID range. Enterprise
	// runtime rules are reassigned after it so separately rendered base and
	// override artifacts cannot reserve the same ModSecurity Rule ID.
	for _, value := range settings.ExcludedIPs {
		appendBypass(PolicyScopeEnterprise, "REMOTE_ADDR", "@ipMatch", value)
	}
	for _, value := range settings.ExcludedPaths {
		appendBypass(PolicyScopeEnterprise, "REQUEST_URI", "@beginsWith", value)
	}
	for _, item := range settings.Exclusions {
		item.ID = randomID()
		item.SourceScope = PolicyScopeEnterprise
		item.Order = len(configuration.Exclusions)
		if item.LoadStage == PolicyExclusionBefore && len(item.Conditions) != 0 {
			item.GeneratedRuleID = generatedID
			generatedID++
		}
		configuration.Exclusions = append(configuration.Exclusions, item)
	}
	appendCustomRules := func(scope, raw string) error {
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		validated, _, err := safeCustomRules(raw)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(validated, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			match := customRuleID.FindStringSubmatch(line)
			if len(match) != 2 {
				return errors.New("custom Rule has no ID")
			}
			ruleID, _ := strconv.Atoi(match[1])
			validRange := scope == PolicyScopeSystem && ruleID >= systemRuleIDMin && ruleID <= systemRuleIDMax || scope == PolicyScopeEnterprise && ruleID >= enterpriseRuleIDMin && ruleID <= enterpriseRuleIDMax
			configuration.CustomRules = append(configuration.CustomRules, PolicyCustomRule{
				ID: randomID(), SourceScope: scope, RuleID: ruleID, Phase: secRuleActionValue(line, "phase"), Severity: secRuleActionValue(line, "severity"),
				CanonicalSecRule: line, Enabled: true, LegacyIDRange: !validRange, Order: len(configuration.CustomRules),
			})
			legacy = legacy || !validRange
		}
		return nil
	}
	if err := appendCustomRules(PolicyScopeSystem, template.Defaults.CustomRules); err != nil {
		return PolicyConfiguration{}, false, err
	}
	if err := appendCustomRules(PolicyScopeEnterprise, settings.CustomRules); err != nil {
		return PolicyConfiguration{}, false, err
	}
	if err := configuration.UpdateDigest(); err != nil {
		return PolicyConfiguration{}, false, err
	}
	if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
		return PolicyConfiguration{}, false, err
	}
	return configuration, legacy, nil
}

func secRuleActionValue(rule, key string) string {
	actions := secRuleActions(rule)
	for _, item := range strings.Split(actions, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(item), ":")
		if ok && strings.EqualFold(name, key) {
			return strings.Trim(strings.TrimSpace(value), "'\"")
		}
	}
	return ""
}

func validateConfigurationRuleIDs(configuration PolicyConfiguration, index crsindex.Index) error {
	if len(configuration.CRSSetupMap()) > mwafSetupRuleIDMax-mwafSetupRuleIDMin+1 {
		return errors.New("CRS setup values exceed the M-WAF generated Rule ID namespace")
	}
	upstreamRules := make(map[int]crsindex.Rule, len(index.Rules))
	upstreamTags := make(map[string]bool)
	for _, rule := range index.Rules {
		upstreamRules[rule.ID] = rule
		for _, tag := range rule.Tags {
			upstreamTags[tag] = true
		}
	}
	setupDefinitions := make(map[string]crsindex.SetupField, len(index.Setup))
	for _, item := range index.Setup {
		setupDefinitions[item.Key] = item
	}
	for _, item := range configuration.Setup {
		definition, ok := setupDefinitions[item.Key]
		if !ok {
			return migrationRequiredf("CRS setup value %q is not supported by the selected release", item.Key)
		}
		if definition.Type == "integer" || definition.Type == "number" {
			if setupValueAllowsUnlimited(item.Key) && strings.EqualFold(item.Value, "unlimited") {
				continue
			}
			value, err := strconv.Atoi(item.Value)
			if err != nil || definition.Minimum != 0 && value < definition.Minimum || definition.Maximum != 0 && value > definition.Maximum {
				return migrationRequiredf("CRS setup value %q is outside its supported range", item.Key)
			}
		} else {
			if len(item.Value) > 4096 || strings.ContainsAny(item.Value, "\"'\\\r\n") {
				return migrationRequiredf("CRS setup value %q contains unsupported characters", item.Key)
			}
			if len(definition.Options) != 0 && !containsString(definition.Options, item.Value) {
				return migrationRequiredf("CRS setup value %q is not an allowed option", item.Key)
			}
		}
	}
	for id := mwafSetupRuleIDMin; id < mwafSetupRuleIDMin+len(configuration.CRSSetupMap()); id++ {
		if upstreamRules[id].ID != 0 {
			return fmt.Errorf("generated CRS setup Rule ID %d conflicts with the selected release", id)
		}
	}
	for _, item := range configuration.Exclusions {
		if item.GeneratedRuleID != 0 && upstreamRules[item.GeneratedRuleID].ID != 0 {
			return fmt.Errorf("generated exclusion Rule ID %d conflicts with the selected release", item.GeneratedRuleID)
		}
		rule := upstreamRules[item.RuleID]
		if (item.Type == PolicyExclusionRule || item.Type == PolicyExclusionTarget) && rule.ID == 0 {
			return migrationRequiredf("exclusion references Rule ID %d that is absent from the selected CRS release", item.RuleID)
		}
		if item.Type == PolicyExclusionTarget && !ruleHasTarget(rule, item.Target) {
			return migrationRequiredf("target exclusion references %q which is absent from CRS Rule %d", item.Target, item.RuleID)
		}
		if item.Type == PolicyExclusionTag && !upstreamTags[item.RuleTag] {
			return migrationRequiredf("exclusion references tag %q that is absent from the selected CRS release", item.RuleTag)
		}
	}
	for _, item := range configuration.CustomRules {
		if item.LegacyIDRange {
			return migrationRequiredf("legacy custom Rule ID %d must be moved into the current %s namespace before creating a new revision", item.RuleID, item.SourceScope)
		}
		if upstreamRules[item.RuleID].ID != 0 {
			return migrationRequiredf("custom Rule ID %d conflicts with the selected CRS release", item.RuleID)
		}
	}
	for _, item := range configuration.IPRules {
		if upstreamRules[item.GeneratedRuleID].ID != 0 {
			return migrationRequiredf("generated IP Rule ID %d conflicts with the selected CRS release", item.GeneratedRuleID)
		}
	}
	return nil
}

func isCorePolicySetupKey(key string) bool {
	switch key {
	case "blocking_paranoia_level", "detection_paranoia_level", "inbound_anomaly_score_threshold", "outbound_anomaly_score_threshold", "early_blocking", "sampling_percentage":
		return true
	default:
		return false
	}
}

func setupValueAllowsUnlimited(key string) bool {
	return key == "max_file_size" || key == "combined_file_sizes"
}
