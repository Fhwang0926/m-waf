package manager

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Fhwang0926/m-waf/internal/policybundle"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const policyDeliveryFormatSplit = "base-plus-override-v1"

type policyOverrideSnapshot struct {
	ScalarSource string                 `json:"scalar_source"`
	Scalars      *PolicyScalarOverrides `json:"scalars,omitempty"`
	Setup        []CRSSetupValue        `json:"setup,omitempty"`
	Exclusions   []PolicyExclusion      `json:"exclusions,omitempty"`
	CustomRules  []PolicyCustomRule     `json:"custom_rules,omitempty"`
	IPRules      []PolicyIPRule         `json:"ip_rules,omitempty"`
}

type policyValidationDigestInput struct {
	BasePolicyID          string `json:"base_policy_id"`
	BasePolicySHA256      string `json:"base_policy_sha256"`
	BaseArtifactSHA256    string `json:"base_artifact_sha256"`
	CRSReleaseID          string `json:"crs_release_id"`
	CRSIndexSHA256        string `json:"crs_index_sha256"`
	OverrideConfigSHA256  string `json:"override_config_sha256"`
	EffectiveConfigSHA256 string `json:"effective_config_sha256"`
	Renderer              string `json:"renderer"`
}

func (s *Server) prepareSplitPolicyArtifacts(ctx context.Context, policyTemplate systempolicy.Template, configuration PolicyConfiguration, scalarSource string, scalarOverrides *PolicyScalarOverrides) ([]byte, *PolicyDeliveryMetadata, error) {
	if policyTemplate.Defaults.CRSSource == nil || policyTemplate.Defaults.ArtifactFormat != policybundle.FormatV3 {
		return nil, nil, errors.New("split policy delivery requires a self-contained verified CRS source")
	}
	baseConfiguration, err := s.store.PolicyConfigurationBySystemPolicyID(ctx, policyTemplate.Reference())
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, err
		}
		settings := PolicySettings{
			ParanoiaLevel: policyTemplate.Defaults.ParanoiaLevel, ExecutingParanoiaLevel: policyTemplate.Defaults.ExecutingParanoiaLevel,
			InboundScore: policyTemplate.Defaults.InboundScore, OutboundScore: policyTemplate.Defaults.OutboundScore,
			RequestBody: policyTemplate.Defaults.RequestBody, ResponseBody: policyTemplate.Defaults.ResponseBody,
			EarlyBlocking: policyTemplate.Defaults.EarlyBlocking, SamplingPercentage: policyTemplate.Defaults.SamplingPercentage,
		}
		baseConfiguration, _, err = structuredConfigurationFromPolicy(policyTemplate.Reference(), "", policyTemplate, policyTemplate.Defaults.Mode, settings)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := baseConfiguration.ValidateAt(currentPolicyValidationTime()); err != nil {
		return nil, nil, fmt.Errorf("validate base policy: %w", err)
	}
	if err := configuration.ValidateAt(currentPolicyValidationTime()); err != nil {
		return nil, nil, fmt.Errorf("validate effective policy: %w", err)
	}
	if err := validatePolicyComposition(baseConfiguration, configuration, scalarSource); err != nil {
		return nil, nil, fmt.Errorf("validate base and override composition: %w", err)
	}
	source, sourceIndex, found, err := s.indexedPolicySource(ctx, configuration.CRSReleaseID)
	if err != nil {
		return nil, nil, err
	}
	if !found || source.ID != policyTemplate.Defaults.CRSSource.ID {
		return nil, nil, errors.New("validated CRS source for split policy is unavailable")
	}
	if err := validateConfigurationRuleIDs(configuration, sourceIndex); err != nil {
		return nil, nil, err
	}
	files, err := s.policySourceFiles(policyTemplate.Defaults.CRSSource.ID)
	if err != nil {
		return nil, nil, err
	}
	baseRaw, baseManifest, err := policybundle.BuildBaseWithCRS(policyTemplate.Reference(), *policyTemplate.Defaults.CRSSource, policyBundleInputFromConfiguration(baseConfiguration), files)
	if err != nil {
		return nil, nil, err
	}
	baseSHA256, baseSignature := s.policySigner.Sign(baseRaw)
	if baseManifest.BasePolicyID != policyTemplate.Reference() {
		return nil, nil, errors.New("base policy manifest identity mismatch")
	}

	overrideInput, snapshot := policyOverrideFromConfiguration(configuration, scalarSource, scalarOverrides)
	overrideRaw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, nil, err
	}
	overrideDigest := sha256.Sum256(overrideRaw)
	overrideSHA256 := hex.EncodeToString(overrideDigest[:])
	basePolicySHA256 := policyTemplate.Digest
	if basePolicySHA256 == "" {
		basePolicySHA256 = baseConfiguration.ConfigSHA256
	}
	validationRaw, err := json.Marshal(policyValidationDigestInput{
		BasePolicyID: policyTemplate.Reference(), BasePolicySHA256: basePolicySHA256, BaseArtifactSHA256: baseSHA256,
		CRSReleaseID: source.ID, CRSIndexSHA256: source.IndexSHA256, OverrideConfigSHA256: overrideSHA256,
		EffectiveConfigSHA256: configuration.ConfigSHA256, Renderer: policybundle.FormatOverride,
	})
	if err != nil {
		return nil, nil, err
	}
	validationHash := sha256.Sum256(validationRaw)
	validationDigest := hex.EncodeToString(validationHash[:])
	overrideArtifact, overrideManifest, err := policybundle.BuildOverride(*policyTemplate.Defaults.CRSSource, overrideInput, policybundle.OverrideMetadata{
		BasePolicyID: policyTemplate.Reference(), BaseArtifactSHA256: baseSHA256, OverrideConfigSHA256: overrideSHA256,
		EffectiveConfigSHA256: configuration.ConfigSHA256, ValidationDigest: validationDigest,
	})
	if err != nil {
		return nil, nil, err
	}
	parsedBase, _, err := policybundle.Parse(baseRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("validate rendered base policy: %w", err)
	}
	parsedOverride, _, err := policybundle.Parse(overrideArtifact)
	if err != nil {
		return nil, nil, fmt.Errorf("validate rendered override policy: %w", err)
	}
	if parsedBase.BasePolicyID != parsedOverride.BasePolicyID || parsedOverride.BaseArtifactSHA256 != baseSHA256 || parsedOverride.ValidationDigest != validationDigest || overrideManifest.EffectiveConfigSHA256 != configuration.ConfigSHA256 {
		return nil, nil, errors.New("backend policy composition validation failed")
	}
	baseRelativePath := filepath.Join("policy-bases", baseSHA256+".base.tar.gz")
	if err := writeArtifact(filepath.Join(s.cfg.ArtifactRoot, baseRelativePath), baseRaw); err != nil {
		return nil, nil, err
	}
	return overrideArtifact, &PolicyDeliveryMetadata{
		Format: policyDeliveryFormatSplit, BasePolicyID: policyTemplate.Reference(), BasePolicySHA256: basePolicySHA256,
		BaseArtifactPath: filepath.ToSlash(baseRelativePath), BaseArtifactSHA256: baseSHA256, BaseArtifactSignature: baseSignature,
		OverrideConfigSHA256: overrideSHA256, EffectiveConfigSHA256: configuration.ConfigSHA256, ValidationDigest: validationDigest,
	}, nil
}

func validatePolicyComposition(baseConfiguration, effectiveConfiguration PolicyConfiguration, scalarSource string) error {
	if baseConfiguration.CRSReleaseID != effectiveConfiguration.CRSReleaseID || baseConfiguration.RuleIDNamespaceVersion != effectiveConfiguration.RuleIDNamespaceVersion {
		return errors.New("effective policy does not use the selected base CRS identity")
	}
	if scalarSource == PolicyScalarSourceInherit && (baseConfiguration.EngineMode != effectiveConfiguration.EngineMode ||
		baseConfiguration.BlockingParanoiaLevel != effectiveConfiguration.BlockingParanoiaLevel ||
		baseConfiguration.ExecutingParanoiaLevel != effectiveConfiguration.ExecutingParanoiaLevel ||
		baseConfiguration.InboundAnomalyThreshold != effectiveConfiguration.InboundAnomalyThreshold ||
		baseConfiguration.OutboundAnomalyThreshold != effectiveConfiguration.OutboundAnomalyThreshold ||
		baseConfiguration.RequestBodyAccess != effectiveConfiguration.RequestBodyAccess ||
		baseConfiguration.ResponseBodyAccess != effectiveConfiguration.ResponseBodyAccess ||
		baseConfiguration.EarlyBlocking != effectiveConfiguration.EarlyBlocking ||
		baseConfiguration.SamplingPercentage != effectiveConfiguration.SamplingPercentage) {
		return errors.New("inherited policy scalars differ from the base policy")
	}
	baseSystem, err := systemPolicyOverlayDigest(baseConfiguration)
	if err != nil {
		return err
	}
	effectiveSystem, err := systemPolicyOverlayDigest(effectiveConfiguration)
	if err != nil {
		return err
	}
	if baseSystem != effectiveSystem {
		return errors.New("effective policy changes the immutable system overlay")
	}
	return nil
}

func systemPolicyOverlayDigest(configuration PolicyConfiguration) (string, error) {
	type systemOverlay struct {
		Setup       []CRSSetupValue    `json:"setup,omitempty"`
		Exclusions  []PolicyExclusion  `json:"exclusions,omitempty"`
		CustomRules []PolicyCustomRule `json:"custom_rules,omitempty"`
		IPRules     []PolicyIPRule     `json:"ip_rules,omitempty"`
	}
	var snapshot systemOverlay
	for _, item := range configuration.Setup {
		if item.SourceScope == PolicyScopeSystem {
			snapshot.Setup = append(snapshot.Setup, item)
		}
	}
	for _, item := range configuration.Exclusions {
		if item.SourceScope == PolicyScopeSystem {
			item.ID = ""
			snapshot.Exclusions = append(snapshot.Exclusions, item)
		}
	}
	for _, item := range configuration.CustomRules {
		if item.SourceScope == PolicyScopeSystem {
			item.ID = ""
			snapshot.CustomRules = append(snapshot.CustomRules, item)
		}
	}
	for _, item := range configuration.IPRules {
		if item.SourceScope == PolicyScopeSystem {
			item.ID = ""
			snapshot.IPRules = append(snapshot.IPRules, item)
		}
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func policyOverrideFromConfiguration(configuration PolicyConfiguration, scalarSource string, scalarOverrides *PolicyScalarOverrides) (policybundle.OverrideInput, policyOverrideSnapshot) {
	includeScalars := scalarSource != PolicyScalarSourceInherit
	input := policybundle.OverrideInput{
		IncludeScalars: includeScalars, Mode: configuration.EngineMode, RequestBody: configuration.RequestBodyAccess,
		ResponseBody: configuration.ResponseBodyAccess,
	}
	snapshot := policyOverrideSnapshot{ScalarSource: scalarSource}
	if includeScalars {
		if scalarOverrides == nil {
			scalarOverrides = &PolicyScalarOverrides{
				Mode: configuration.EngineMode, ParanoiaLevel: configuration.BlockingParanoiaLevel,
				ExecutingParanoiaLevel: configuration.ExecutingParanoiaLevel, InboundScore: configuration.InboundAnomalyThreshold,
				OutboundScore: configuration.OutboundAnomalyThreshold, RequestBody: configuration.RequestBodyAccess,
				ResponseBody: configuration.ResponseBodyAccess, EarlyBlocking: configuration.EarlyBlocking,
				SamplingPercentage: configuration.SamplingPercentage,
			}
		}
		snapshot.Scalars = scalarOverrides
		input.CRSSetup = configuration.CRSSetupMap()
	}
	for _, item := range configuration.Setup {
		if item.SourceScope != PolicyScopeEnterprise {
			continue
		}
		snapshot.Setup = append(snapshot.Setup, item)
		if input.CRSSetup == nil {
			input.CRSSetup = make(map[string]string)
		}
		input.CRSSetup[item.Key] = item.Value
	}
	for _, item := range configuration.Exclusions {
		if item.SourceScope == PolicyScopeEnterprise {
			snapshot.Exclusions = append(snapshot.Exclusions, item)
			input.Exclusions = append(input.Exclusions, policyBundleExclusion(item))
		}
	}
	for _, item := range configuration.CustomRules {
		if item.SourceScope == PolicyScopeEnterprise {
			snapshot.CustomRules = append(snapshot.CustomRules, item)
			input.CustomRules = append(input.CustomRules, policybundle.CustomRule{RuleID: item.RuleID, Scope: item.SourceScope, Canonical: item.CanonicalSecRule, Enabled: item.Enabled})
		}
	}
	for _, item := range configuration.IPRules {
		if item.SourceScope == PolicyScopeEnterprise {
			snapshot.IPRules = append(snapshot.IPRules, item)
			input.IPRules = append(input.IPRules, policybundle.IPRule{Action: item.Action, Network: item.Network, GeneratedRuleID: item.GeneratedRuleID, Enabled: item.Enabled})
		}
	}
	return input, snapshot
}

func policyBundleExclusion(item PolicyExclusion) policybundle.Exclusion {
	exclusion := policybundle.Exclusion{
		Type: item.Type, LoadStage: item.LoadStage, RuleID: item.RuleID, RuleTag: item.RuleTag, Target: item.Target,
		GeneratedRuleID: item.GeneratedRuleID, Enabled: item.Enabled,
	}
	for _, condition := range item.Conditions {
		exclusion.Conditions = append(exclusion.Conditions, policybundle.Condition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value})
	}
	return exclusion
}

func currentPolicyValidationTime() time.Time {
	return time.Now().UTC()
}
