package manager

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Fhwang0926/m-waf/internal/policybundle"
)

func (s *Server) prepareConfigurationRevision(ctx context.Context, policy EnterprisePolicyRecord, configuration PolicyConfiguration, origin string) (PolicyRevisionInput, string, error) {
	templateItem, ok := s.systemPolicyTemplate(ctx, policy.CurrentSystemPolicyID)
	if !ok || templateItem.Defaults.CRSSource == nil || configuration.CRSReleaseID == "" {
		return PolicyRevisionInput{}, "", errors.New("structured signed policy source is unavailable")
	}
	revisionID := randomID()
	configuration.ID = randomID()
	configuration.SystemPolicyVersionID = ""
	configuration.PolicyRevisionID = revisionID
	for index := range configuration.Exclusions {
		configuration.Exclusions[index].ID = randomID()
	}
	for index := range configuration.CustomRules {
		configuration.CustomRules[index].ID = randomID()
	}
	for index := range configuration.IPRules {
		configuration.IPRules[index].ID = randomID()
	}
	now := time.Now().UTC()
	activeIPRules := configuration.IPRules[:0]
	for _, rule := range configuration.IPRules {
		if rule.ExpiresAt != nil && !rule.ExpiresAt.After(now) {
			continue
		}
		activeIPRules = append(activeIPRules, rule)
	}
	configuration.IPRules = activeIPRules
	if err := configuration.UpdateDigest(); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	if err := configuration.ValidateAt(now); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	_, sourceIndex, found, err := s.indexedPolicySource(ctx, configuration.CRSReleaseID)
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	if !found {
		return PolicyRevisionInput{}, "", errors.New("verified CRS source index is unavailable")
	}
	if err := validateConfigurationRuleIDs(configuration, sourceIndex); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	input := policyBundleInputFromConfiguration(configuration)
	var artifact []byte
	switch templateItem.Defaults.ArtifactFormat {
	case policybundle.FormatV3:
		files, filesErr := s.policySourceFiles(templateItem.Defaults.CRSSource.ID)
		if filesErr != nil {
			return PolicyRevisionInput{}, "", filesErr
		}
		artifact, _, err = policybundle.BuildWithCRS(*templateItem.Defaults.CRSSource, input, files)
	case policybundle.Format:
		artifact, _, err = policybundle.Build(*templateItem.Defaults.CRSSource, input)
	default:
		return PolicyRevisionInput{}, "", errors.New("event actions require policy-bundle-v2 or policy-bundle-v3")
	}
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	settings := configuration.ApplyToSettings(policy.CurrentSettings)
	settings.PolicyOrigin = origin
	settings.MigratedFrom = policy.CurrentRevisionID
	settings.ArtifactFormat = templateItem.Defaults.ArtifactFormat
	settingsRaw, err := json.Marshal(settings)
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	hash, signature := s.policySigner.Sign(artifact)
	extension := ".tar.gz"
	if templateItem.Defaults.ArtifactFormat == policybundle.FormatV3 {
		extension = ".v3.tar.gz"
	}
	relativePath := filepath.Join("policies", revisionID+extension)
	fullPath := filepath.Join(s.cfg.ArtifactRoot, relativePath)
	if err := writeArtifact(fullPath, artifact); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	return PolicyRevisionInput{
		ID: revisionID, SystemPolicyVersionID: policy.CurrentSystemPolicyID, ParentRevisionID: policy.CurrentRevisionID,
		Name: policy.Name, Description: policy.Description, Mode: configuration.EngineMode, SettingsJSON: string(settingsRaw),
		ArtifactPath: filepath.ToSlash(relativePath), ArtifactSHA256: hash, ArtifactSignature: signature,
		PolicyOrigin: origin, Configuration: &configuration,
	}, fullPath, nil
}

func (s *Server) createConfigurationRollout(ctx context.Context, policy EnterprisePolicyRecord, expectedRevisionID, actorID, origin string, configuration PolicyConfiguration) (string, error) {
	if policy.Status != EnterprisePolicyActive || policy.CurrentRevisionID != expectedRevisionID || policy.HasActiveRollout {
		return "", errors.New("enterprise policy revision changed or has active rollout")
	}
	serverIDs, err := s.store.ListPolicyServerIDs(ctx, policy.EnterpriseID, policy.ID)
	if err != nil {
		return "", err
	}
	if len(serverIDs) == 0 {
		return "", errors.New("enterprise policy has no assigned servers")
	}
	revision, fullPath, err := s.prepareConfigurationRevision(ctx, policy, configuration, origin)
	if err != nil {
		return "", err
	}
	rolloutID, err := s.store.CreatePolicyRollout(ctx, policy, expectedRevisionID, "UPDATE", "QUEUED", actorID, &revision, revision.ID, policy.CurrentSystemPolicyID, serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		return "", err
	}
	return rolloutID, nil
}

func nextGeneratedPolicyRuleID(configuration PolicyConfiguration) (int, error) {
	used := make(map[int]bool)
	for _, item := range configuration.Exclusions {
		used[item.GeneratedRuleID] = item.GeneratedRuleID != 0
	}
	for _, item := range configuration.IPRules {
		used[item.GeneratedRuleID] = item.GeneratedRuleID != 0
	}
	for id := mwafGeneratedRuleIDMin; id <= mwafGeneratedRuleIDMax; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("generated policy Rule ID namespace is exhausted")
}

func (s *Server) ExpireIPRules(ctx context.Context) error {
	policyIDs, err := s.store.PoliciesWithExpiredIPRules(ctx, time.Now().UTC(), 100)
	if err != nil {
		return err
	}
	for _, policyID := range policyIDs {
		policy, err := s.store.EnterprisePolicyByID(ctx, "", policyID)
		if err != nil || policy.HasActiveRollout {
			continue
		}
		configuration, err := currentPolicyConfiguration(ctx, s.store, policy)
		if err != nil {
			continue
		}
		before := len(configuration.IPRules)
		now := time.Now().UTC()
		next := configuration.IPRules[:0]
		for _, rule := range configuration.IPRules {
			if rule.ExpiresAt != nil && !rule.ExpiresAt.After(now) {
				continue
			}
			rule.Order = len(next)
			next = append(next, rule)
		}
		if len(next) == before {
			continue
		}
		configuration.IPRules = next
		rolloutID, err := s.createConfigurationRollout(ctx, policy, policy.CurrentRevisionID, "", "ip-rule-expiry", configuration)
		if err != nil {
			_ = s.store.Audit(ctx, randomID(), "system:ip-expiry", "enterprise_policy.ip_rule_expiry", policy.ID+":"+err.Error(), "failed", "internal")
			continue
		}
		_ = s.store.Audit(ctx, randomID(), "system:ip-expiry", "enterprise_policy.ip_rule_expiry", policy.ID+":"+rolloutID, "success", "internal")
		s.TriggerPolicySync()
	}
	return nil
}
