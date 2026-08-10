package policybundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const (
	Format         = "policy-bundle-v2"
	FormatV3       = "policy-bundle-v3"
	FormatBase     = "policy-base-v1"
	FormatOverride = "policy-override-v1"
)

var orderedFiles = []string{
	"00-engine.conf",
	"20-crs-setup.conf",
	"30-before-crs-exclusions.conf",
	"40-crs-rules.conf",
	"50-after-crs-exclusions.conf",
	"60-service-rules.conf",
}

var baseOrderedFiles = []string{
	"00-base-engine.conf",
	"20-base-crs-setup.conf",
	"30-base-before-crs-exclusions.conf",
	"40-base-crs-rules.conf",
	"50-base-after-crs-exclusions.conf",
	"60-base-service-rules.conf",
}

var overrideOrderedFiles = []string{
	"10-enterprise-engine.conf",
	"25-enterprise-crs-setup.conf",
	"35-enterprise-before-crs-exclusions.conf",
	"55-enterprise-after-crs-exclusions.conf",
	"65-enterprise-service-rules.conf",
}

type FileManifest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion         int                          `json:"schema_version"`
	ArtifactFormat        string                       `json:"artifact_format"`
	PolicySource          systempolicy.PolicySourceRef `json:"policy_source"`
	BasePolicyID          string                       `json:"base_policy_id,omitempty"`
	BaseArtifactSHA256    string                       `json:"base_artifact_sha256,omitempty"`
	OverrideConfigSHA256  string                       `json:"override_config_sha256,omitempty"`
	EffectiveConfigSHA256 string                       `json:"effective_config_sha256,omitempty"`
	ValidationDigest      string                       `json:"validation_digest,omitempty"`
	Files                 []FileManifest               `json:"files"`
}

type Input struct {
	Mode            string
	RequestBody     bool
	ResponseBody    bool
	CRSSetup        map[string]string
	Before          []systempolicy.RuleExclusion
	After           []systempolicy.RuleExclusion
	Target          []systempolicy.TargetExclusion
	ExcludedPaths   []string
	ExcludedIPs     []string
	SystemRules     string
	EnterpriseRules string
	Exclusions      []Exclusion
	CustomRules     []CustomRule
	IPRules         []IPRule
}

type Condition struct {
	Field    string
	Operator string
	Value    string
}

type Exclusion struct {
	Type            string
	LoadStage       string
	RuleID          int
	RuleTag         string
	Target          string
	GeneratedRuleID int
	Enabled         bool
	Conditions      []Condition
}

type CustomRule struct {
	RuleID    int
	Scope     string
	Canonical string
	Enabled   bool
}

type IPRule struct {
	Action          string
	Network         string
	GeneratedRuleID int
	Enabled         bool
}

type OverrideInput struct {
	IncludeScalars bool
	Mode           string
	RequestBody    bool
	ResponseBody   bool
	CRSSetup       map[string]string
	Exclusions     []Exclusion
	CustomRules    []CustomRule
	IPRules        []IPRule
}

type OverrideMetadata struct {
	BasePolicyID          string
	BaseArtifactSHA256    string
	OverrideConfigSHA256  string
	EffectiveConfigSHA256 string
	ValidationDigest      string
}

func Build(source systempolicy.PolicySourceRef, input Input) ([]byte, Manifest, error) {
	if source.ID == "" || source.Commit == "" || len(source.IndexSHA256) != 64 {
		return nil, Manifest{}, errors.New("verified CRS policy source is required")
	}
	if input.Mode != "DetectionOnly" && input.Mode != "On" {
		return nil, Manifest{}, errors.New("policy mode must be DetectionOnly or On")
	}
	files := map[string][]byte{
		"00-engine.conf":                []byte(renderEngine(input.Mode, input.RequestBody, input.ResponseBody)),
		"20-crs-setup.conf":             []byte(renderSetup(input.CRSSetup)),
		"30-before-crs-exclusions.conf": []byte(renderBefore(input)),
		"40-crs-rules.conf":             []byte("# Immutable OWASP CRS rules supplied by the signed module package.\nInclude /usr/share/mwaf/crs/rules/*.conf\n"),
		"50-after-crs-exclusions.conf":  []byte(renderAfter(input)),
		"60-service-rules.conf":         []byte(renderServiceRules(input)),
	}
	return buildArchive(source, Format, 2, files, orderedFiles, Manifest{})
}

// BuildWithCRS creates a self-contained revision. The upstream CRS files remain
// unchanged and switch atomically together with the M-WAF overlay.
func BuildWithCRS(source systempolicy.PolicySourceRef, input Input, crsFiles map[string][]byte) ([]byte, Manifest, error) {
	if source.ID == "" || source.Commit == "" || len(source.IndexSHA256) != 64 {
		return nil, Manifest{}, errors.New("verified CRS policy source is required")
	}
	if input.Mode != "DetectionOnly" && input.Mode != "On" {
		return nil, Manifest{}, errors.New("policy mode must be DetectionOnly or On")
	}
	if crsFiles["crs/crs-setup.conf"] == nil {
		return nil, Manifest{}, errors.New("self-contained policy requires CRS setup")
	}
	files := map[string][]byte{
		"00-engine.conf":                []byte(renderEngine(input.Mode, input.RequestBody, input.ResponseBody)),
		"20-crs-setup.conf":             []byte(renderSetupV3(input.CRSSetup)),
		"30-before-crs-exclusions.conf": []byte(renderBefore(input)),
		"40-crs-rules.conf":             []byte("# Immutable OWASP CRS rules carried by this signed policy revision.\nInclude /etc/mwaf/active/crs/rules/*.conf\n"),
		"50-after-crs-exclusions.conf":  []byte(renderAfter(input)),
		"60-service-rules.conf":         []byte(renderServiceRules(input)),
	}
	names := append([]string(nil), orderedFiles...)
	crsNames := make([]string, 0, len(crsFiles))
	for name, raw := range crsFiles {
		clean := path.Clean(name)
		if clean != name || !strings.HasPrefix(name, "crs/") || strings.HasPrefix(name, "crs/../") || len(raw) > 8<<20 {
			return nil, Manifest{}, fmt.Errorf("unsafe CRS policy file %q", name)
		}
		files[name] = raw
		crsNames = append(crsNames, name)
	}
	sort.Strings(crsNames)
	names = append(names, crsNames...)
	return buildArchive(source, FormatV3, 3, files, names, Manifest{})
}

// BuildBaseWithCRS creates the immutable base policy. Enterprise settings are
// deliberately excluded and arrive in a separately signed override artifact.
func BuildBaseWithCRS(basePolicyID string, source systempolicy.PolicySourceRef, input Input, crsFiles map[string][]byte) ([]byte, Manifest, error) {
	if basePolicyID == "" {
		return nil, Manifest{}, errors.New("base policy id is required")
	}
	if source.ID == "" || source.Commit == "" || len(source.IndexSHA256) != 64 {
		return nil, Manifest{}, errors.New("verified CRS policy source is required")
	}
	if input.Mode != "DetectionOnly" && input.Mode != "On" {
		return nil, Manifest{}, errors.New("policy mode must be DetectionOnly or On")
	}
	if crsFiles["crs/crs-setup.conf"] == nil {
		return nil, Manifest{}, errors.New("base policy requires CRS setup")
	}
	files := map[string][]byte{
		"00-base-engine.conf":                []byte(renderEngine(input.Mode, input.RequestBody, input.ResponseBody)),
		"20-base-crs-setup.conf":             []byte(renderSetupV3(input.CRSSetup)),
		"30-base-before-crs-exclusions.conf": []byte(renderBefore(input)),
		"40-base-crs-rules.conf":             []byte("# Immutable OWASP CRS rules carried by this signed base policy.\nInclude /etc/mwaf/active/crs/rules/*.conf\n"),
		"50-base-after-crs-exclusions.conf":  []byte(renderAfter(input)),
		"60-base-service-rules.conf":         []byte(renderServiceRules(input)),
	}
	names := append([]string(nil), baseOrderedFiles...)
	crsNames := make([]string, 0, len(crsFiles))
	for name, raw := range crsFiles {
		clean := path.Clean(name)
		if clean != name || !strings.HasPrefix(name, "crs/") || strings.HasPrefix(name, "crs/../") || len(raw) > 8<<20 {
			return nil, Manifest{}, fmt.Errorf("unsafe CRS policy file %q", name)
		}
		files[name] = raw
		crsNames = append(crsNames, name)
	}
	sort.Strings(crsNames)
	names = append(names, crsNames...)
	return buildArchive(source, FormatBase, 1, files, names, Manifest{BasePolicyID: basePolicyID})
}

// BuildOverride creates only the enterprise layer and pins it to the exact
// signed base artifact that the Manager validated.
func BuildOverride(source systempolicy.PolicySourceRef, input OverrideInput, metadata OverrideMetadata) ([]byte, Manifest, error) {
	if source.ID == "" || source.Commit == "" || len(source.IndexSHA256) != 64 {
		return nil, Manifest{}, errors.New("verified CRS policy source is required")
	}
	if metadata.BasePolicyID == "" || len(metadata.BaseArtifactSHA256) != 64 || len(metadata.OverrideConfigSHA256) != 64 || len(metadata.EffectiveConfigSHA256) != 64 || len(metadata.ValidationDigest) != 64 {
		return nil, Manifest{}, errors.New("validated base and override metadata is required")
	}
	engine := "# Enterprise policy inherits base engine settings.\n"
	setup := "# Enterprise policy inherits base CRS setup.\n"
	if input.IncludeScalars {
		if input.Mode != "DetectionOnly" && input.Mode != "On" {
			return nil, Manifest{}, errors.New("override mode must be DetectionOnly or On")
		}
		engine = renderEngine(input.Mode, input.RequestBody, input.ResponseBody)
		setup = renderSetupValues(input.CRSSetup, 3000)
	}
	overlay := Input{Exclusions: input.Exclusions, CustomRules: input.CustomRules, IPRules: input.IPRules}
	files := map[string][]byte{
		"10-enterprise-engine.conf":                []byte(engine),
		"25-enterprise-crs-setup.conf":             []byte(setup),
		"35-enterprise-before-crs-exclusions.conf": []byte(renderBefore(overlay)),
		"55-enterprise-after-crs-exclusions.conf":  []byte(renderAfter(overlay)),
		"65-enterprise-service-rules.conf":         []byte(renderServiceRules(overlay)),
	}
	seed := Manifest{
		BasePolicyID: metadata.BasePolicyID, BaseArtifactSHA256: metadata.BaseArtifactSHA256,
		OverrideConfigSHA256: metadata.OverrideConfigSHA256, EffectiveConfigSHA256: metadata.EffectiveConfigSHA256,
		ValidationDigest: metadata.ValidationDigest,
	}
	return buildArchive(source, FormatOverride, 1, files, overrideOrderedFiles, seed)
}

func buildArchive(source systempolicy.PolicySourceRef, format string, schemaVersion int, files map[string][]byte, names []string, manifest Manifest) ([]byte, Manifest, error) {
	manifest.SchemaVersion = schemaVersion
	manifest.ArtifactFormat = format
	manifest.PolicySource = source
	var totalSize int64
	for _, name := range names {
		raw, ok := files[name]
		if !ok {
			return nil, Manifest{}, fmt.Errorf("policy file %s is missing", name)
		}
		digest := sha256.Sum256(raw)
		manifest.Files = append(manifest.Files, FileManifest{Path: name, Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])})
		totalSize += int64(len(raw))
	}
	if (format == FormatV3 || format == FormatBase) && totalSize > 64<<20 {
		return nil, Manifest{}, errors.New("self-contained policy files exceed 64 MiB")
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, Manifest{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	var output bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, Manifest{}, err
	}
	compressor.Header.ModTime = time.Unix(0, 0)
	compressor.Header.OS = 255
	archive := tar.NewWriter(compressor)
	write := func(name string, raw []byte) error {
		header := &tar.Header{Name: name, Mode: 0o640, Size: int64(len(raw)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err := archive.Write(raw)
		return err
	}
	if err := write("manifest.json", manifestRaw); err != nil {
		return nil, Manifest{}, err
	}
	for _, name := range names {
		if err := write(name, files[name]); err != nil {
			return nil, Manifest{}, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, Manifest{}, err
	}
	if err := compressor.Close(); err != nil {
		return nil, Manifest{}, err
	}
	limit := 4 << 20
	if format == FormatV3 || format == FormatBase {
		limit = 64 << 20
	}
	if output.Len() > limit {
		return nil, Manifest{}, errors.New("policy bundle exceeds its size limit")
	}
	return output.Bytes(), manifest, nil
}

func Parse(raw []byte) (Manifest, map[string][]byte, error) {
	if len(raw) == 0 || len(raw) > 64<<20 {
		return Manifest{}, nil, errors.New("policy bundle size is invalid")
	}
	compressor, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("open policy bundle: %w", err)
	}
	defer compressor.Close()
	archive := tar.NewReader(compressor)
	files := make(map[string][]byte)
	var totalSize int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, nil, err
		}
		clean := path.Clean(header.Name)
		allowed := header.Name == "manifest.json" || containsName(orderedFiles, header.Name) || containsName(baseOrderedFiles, header.Name) || containsName(overrideOrderedFiles, header.Name) || strings.HasPrefix(header.Name, "crs/")
		if header.Typeflag != tar.TypeReg || clean != header.Name || strings.HasPrefix(clean, "../") || !allowed || header.Size < 0 || header.Size > 8<<20 || totalSize+header.Size > 64<<20 || files[header.Name] != nil || len(files) >= 4096 {
			return Manifest{}, nil, fmt.Errorf("unsafe or unexpected policy bundle entry %q", header.Name)
		}
		content, err := io.ReadAll(io.LimitReader(archive, 8<<20+1))
		if err != nil || int64(len(content)) != header.Size {
			return Manifest{}, nil, errors.New("read policy bundle entry")
		}
		files[header.Name] = content
		totalSize += int64(len(content))
	}
	if files["manifest.json"] == nil {
		return Manifest{}, nil, errors.New("policy bundle manifest is missing")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(files["manifest.json"]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, fmt.Errorf("decode policy manifest: %w", err)
	}
	validV2 := manifest.SchemaVersion == 2 && manifest.ArtifactFormat == Format && len(manifest.Files) == len(orderedFiles)
	validV3 := manifest.SchemaVersion == 3 && manifest.ArtifactFormat == FormatV3 && len(manifest.Files) > len(orderedFiles)
	validBase := manifest.SchemaVersion == 1 && manifest.ArtifactFormat == FormatBase && len(manifest.Files) > len(baseOrderedFiles) && manifest.BasePolicyID != ""
	validOverride := manifest.SchemaVersion == 1 && manifest.ArtifactFormat == FormatOverride && len(manifest.Files) == len(overrideOrderedFiles) && manifest.BasePolicyID != "" && len(manifest.BaseArtifactSHA256) == 64 && len(manifest.OverrideConfigSHA256) == 64 && len(manifest.EffectiveConfigSHA256) == 64 && len(manifest.ValidationDigest) == 64
	if (!validV2 && !validV3 && !validBase && !validOverride) || manifest.PolicySource.ID == "" {
		return Manifest{}, nil, errors.New("policy bundle manifest is invalid")
	}
	coreFiles := orderedFiles
	if validBase {
		coreFiles = baseOrderedFiles
	} else if validOverride {
		coreFiles = overrideOrderedFiles
	}
	seen := make(map[string]bool, len(manifest.Files))
	for index, entry := range manifest.Files {
		if seen[entry.Path] || files[entry.Path] == nil {
			return Manifest{}, nil, errors.New("policy bundle manifest contains an invalid file")
		}
		seen[entry.Path] = true
		if index < len(coreFiles) && entry.Path != coreFiles[index] {
			return Manifest{}, nil, errors.New("policy bundle core file order is invalid")
		}
		if validV2 && !containsName(orderedFiles, entry.Path) {
			return Manifest{}, nil, errors.New("v2 policy bundle contains a CRS payload")
		}
		if (validV3 || validBase) && index >= len(coreFiles) && !strings.HasPrefix(entry.Path, "crs/") {
			return Manifest{}, nil, errors.New("policy bundle contains an invalid CRS path")
		}
		if validOverride && !containsName(overrideOrderedFiles, entry.Path) {
			return Manifest{}, nil, errors.New("override policy contains an unexpected file")
		}
		content := files[entry.Path]
		digest := sha256.Sum256(content)
		if entry.Size != int64(len(content)) || !strings.EqualFold(entry.SHA256, hex.EncodeToString(digest[:])) {
			return Manifest{}, nil, fmt.Errorf("policy bundle file %s failed verification", entry.Path)
		}
	}
	if len(seen)+1 != len(files) || (validV3 || validBase) && files["crs/crs-setup.conf"] == nil {
		return Manifest{}, nil, errors.New("policy bundle contains unlisted or incomplete files")
	}
	delete(files, "manifest.json")
	return manifest, files, nil
}

func containsName(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func renderEngine(mode string, requestBody, responseBody bool) string {
	requestMode := "Off"
	if requestBody {
		requestMode = "On"
	}
	responseMode := "Off"
	if responseBody {
		responseMode = "On"
	}
	return fmt.Sprintf("# Engine settings generated by M-WAF.\nSecRuleEngine %s\nSecRequestBodyAccess %s\nSecResponseBodyAccess %s\n", mode, requestMode, responseMode)
}

func renderSetup(values map[string]string) string {
	var output strings.Builder
	output.WriteString("# Upstream CRS setup followed by reviewed M-WAF overrides.\nInclude /usr/share/mwaf/crs/crs-setup.conf\n")
	output.WriteString(renderSetupValues(values, 1000))
	return output.String()
}

func renderSetupValues(values map[string]string, firstRuleID int) string {
	var output strings.Builder
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		if strings.EqualFold(strings.TrimSpace(values[key]), "unlimited") {
			continue
		}
		value := strings.ReplaceAll(values[key], "'", "")
		fmt.Fprintf(&output, "SecAction \"id:%d,phase:1,pass,nolog,t:none,setvar:'tx.%s=%s'\"\n", firstRuleID+index, key, value)
	}
	return output.String()
}

func renderSetupV3(values map[string]string) string {
	return strings.Replace(renderSetup(values), "/usr/share/mwaf/crs/crs-setup.conf", "/etc/mwaf/active/crs/crs-setup.conf", 1)
}

func renderBefore(input Input) string {
	var output strings.Builder
	output.WriteString("# IP controls and conditional exclusions evaluated before CRS.\n")
	for _, rule := range input.IPRules {
		if !rule.Enabled {
			continue
		}
		switch rule.Action {
		case "BLOCK":
			fmt.Fprintf(&output, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,deny,status:403,log,msg:'M-WAF IP block'\"\n", rule.Network, rule.GeneratedRuleID)
		case "TRUST":
			fmt.Fprintf(&output, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", rule.Network, rule.GeneratedRuleID)
		}
	}
	if len(input.Exclusions) != 0 {
		for _, exclusion := range input.Exclusions {
			if !exclusion.Enabled || exclusion.LoadStage != "BEFORE_CRS" || len(exclusion.Conditions) == 0 {
				continue
			}
			writeStructuredConditionalRule(&output, exclusion)
		}
		return output.String()
	}
	nextID := 5000
	for _, exclusion := range input.Before {
		if len(exclusion.Conditions) == 0 {
			continue
		}
		writeConditionalRule(&output, nextID, exclusion.RuleID, "", exclusion.Conditions)
		nextID++
	}
	for _, exclusion := range input.Target {
		if len(exclusion.Conditions) == 0 {
			continue
		}
		writeConditionalRule(&output, nextID, exclusion.RuleID, exclusion.Target, exclusion.Conditions)
		nextID++
	}
	for _, ip := range input.ExcludedIPs {
		fmt.Fprintf(&output, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", ip, nextID)
		nextID++
	}
	for _, requestPath := range input.ExcludedPaths {
		fmt.Fprintf(&output, "SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n", requestPath, nextID)
		nextID++
	}
	return output.String()
}

func writeStructuredConditionalRule(output *strings.Builder, exclusion Exclusion) {
	for index, condition := range exclusion.Conditions {
		action := "chain"
		if index == len(exclusion.Conditions)-1 {
			switch exclusion.Type {
			case "RULE":
				action = "ctl:ruleRemoveById=" + strconv.Itoa(exclusion.RuleID)
			case "TARGET":
				action = "ctl:ruleRemoveTargetById=" + strconv.Itoa(exclusion.RuleID) + ";" + exclusion.Target
			case "TAG":
				action = "ctl:ruleRemoveByTag=" + exclusion.RuleTag
			case "ENGINE_BYPASS":
				action = "ctl:ruleEngine=Off"
			}
		}
		if index == 0 {
			fmt.Fprintf(output, "SecRule %s \"%s %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", condition.Field, condition.Operator, condition.Value, exclusion.GeneratedRuleID, action)
		} else {
			fmt.Fprintf(output, "SecRule %s \"%s %s\" \"t:none,%s\"\n", condition.Field, condition.Operator, condition.Value, action)
		}
	}
}

func writeConditionalRule(output *strings.Builder, id, ruleID int, target string, conditions []systempolicy.RuleCondition) {
	for index, condition := range conditions {
		action := "chain"
		if index == len(conditions)-1 {
			ctl := "ctl:ruleRemoveById=" + strconv.Itoa(ruleID)
			if target != "" {
				ctl = "ctl:ruleRemoveTargetById=" + strconv.Itoa(ruleID) + ";" + target
			}
			action = ctl
		}
		if index == 0 {
			fmt.Fprintf(output, "SecRule %s \"%s %s\" \"id:%d,phase:1,pass,nolog,%s\"\n", condition.Field, condition.Operator, condition.Value, id, action)
		} else {
			fmt.Fprintf(output, "SecRule %s \"%s %s\" \"t:none,%s\"\n", condition.Field, condition.Operator, condition.Value, action)
		}
	}
}

func renderAfter(input Input) string {
	var output strings.Builder
	output.WriteString("# Static exclusions evaluated after CRS is loaded.\n")
	if len(input.Exclusions) != 0 {
		for _, exclusion := range input.Exclusions {
			if !exclusion.Enabled || exclusion.LoadStage != "AFTER_CRS" || len(exclusion.Conditions) != 0 {
				continue
			}
			switch exclusion.Type {
			case "RULE":
				fmt.Fprintf(&output, "SecRuleRemoveById %d\n", exclusion.RuleID)
			case "TARGET":
				fmt.Fprintf(&output, "SecRuleUpdateTargetById %d !%s\n", exclusion.RuleID, strings.TrimPrefix(exclusion.Target, "!"))
			case "TAG":
				fmt.Fprintf(&output, "SecRuleRemoveByTag %s\n", exclusion.RuleTag)
			}
		}
		return output.String()
	}
	for _, exclusion := range input.After {
		if len(exclusion.Conditions) != 0 {
			continue
		}
		fmt.Fprintf(&output, "SecRuleRemoveById %d\n", exclusion.RuleID)
	}
	for _, exclusion := range input.Target {
		if len(exclusion.Conditions) != 0 {
			continue
		}
		fmt.Fprintf(&output, "SecRuleUpdateTargetById %d !%s\n", exclusion.RuleID, strings.TrimPrefix(exclusion.Target, "!"))
	}
	return output.String()
}

func renderServiceRules(input Input) string {
	var output strings.Builder
	output.WriteString("# M-WAF service and enterprise rules.\n")
	if len(input.CustomRules) != 0 {
		for _, rule := range input.CustomRules {
			if rule.Enabled && strings.TrimSpace(rule.Canonical) != "" {
				output.WriteString(strings.TrimSpace(rule.Canonical))
				output.WriteByte('\n')
			}
		}
		return output.String()
	}
	for _, rules := range []string{input.SystemRules, input.EnterpriseRules} {
		if value := strings.TrimSpace(rules); value != "" {
			output.WriteString(value)
			output.WriteByte('\n')
		}
	}
	return output.String()
}
