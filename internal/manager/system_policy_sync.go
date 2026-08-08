package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/policybundle"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const systemPolicyServerLimit = 5000

func (s *Server) SyncSystemPolicies(ctx context.Context) error {
	s.policySyncMu.Lock()
	defer s.policySyncMu.Unlock()

	if err := s.syncCRSReleaseIndexes(ctx); err != nil {
		return fmt.Errorf("index verified CRS sources: %w", err)
	}
	if err := s.store.BackfillEnterprisePolicyDomains(ctx); err != nil {
		return fmt.Errorf("backfill enterprise policies: %w", err)
	}
	if err := s.store.BackfillStructuredPolicyConfigurations(ctx); err != nil {
		return fmt.Errorf("backfill structured policy configurations: %w", err)
	}
	servers, err := s.store.ListServers(ctx, "", systemPolicyServerLimit)
	if err != nil {
		return err
	}
	policies, err := s.store.ListEnterprisePolicies(ctx, "", systemPolicyServerLimit)
	if err != nil {
		return err
	}
	var syncErrors []error
	if err := s.seedEnterprisePolicies(ctx, servers, policies); err != nil {
		syncErrors = append(syncErrors, err)
	}
	policies, err = s.store.ListEnterprisePolicies(ctx, "", systemPolicyServerLimit)
	if err != nil {
		return errors.Join(syncErrors...)
	}
	winners, err := s.enterprisePolicyWinners(ctx, policies, servers)
	if err != nil {
		syncErrors = append(syncErrors, err)
	}
	for _, policy := range policies {
		if err := s.prepareAvailablePolicyUpdate(ctx, policy, winners[policy.ID], servers); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("prepare enterprise policy %s update: %w", policy.ID, err))
		}
	}
	rollouts, err := s.store.ListActivePolicyRollouts(ctx)
	if err != nil {
		syncErrors = append(syncErrors, err)
	} else {
		for _, rollout := range rollouts {
			if err := s.processPolicyRollout(ctx, rollout); err != nil {
				syncErrors = append(syncErrors, fmt.Errorf("process policy rollout %s: %w", rollout.ID, err))
			}
		}
	}
	if err := s.reconcileEnterprisePolicyMembership(ctx, policies, winners, servers); err != nil {
		syncErrors = append(syncErrors, err)
	}
	return errors.Join(syncErrors...)
}

func (s *Server) seedEnterprisePolicies(ctx context.Context, servers []ServerRecord, policies []EnterprisePolicyRecord) error {
	hasEnterpriseDefault := make(map[string]bool)
	for _, policy := range policies {
		kind, id, ok := strings.Cut(policy.Target, ":")
		if ok && kind == "enterprise" && id == policy.EnterpriseID {
			hasEnterpriseDefault[policy.EnterpriseID] = true
		}
	}
	enterprises, err := s.store.ListEnterprises(ctx)
	if err != nil {
		return fmt.Errorf("list enterprises for default policy seed: %w", err)
	}
	targets := make(map[string][]ServerRecord)
	for _, enterprise := range enterprises {
		if !hasEnterpriseDefault[enterprise.ID] {
			targets[enterprise.ID] = nil
		}
	}
	for _, server := range servers {
		if !server.Revoked && server.EnterpriseID != "" && server.DesiredPolicyRevision == "" && !hasEnterpriseDefault[server.EnterpriseID] {
			targets[server.EnterpriseID] = append(targets[server.EnterpriseID], server)
		}
	}
	policyTemplate := s.defaultSystemPolicyTemplate(ctx)
	if policyTemplate.Reference() == "@" {
		// A clean installation waits until a system administrator publishes the
		// first canonical crs-baseline from a verified CRS source.
		return nil
	}
	var seedErrors []error
	for enterpriseID, targetServers := range targets {
		policyID := randomID()
		settings := PolicySettings{
			SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
			CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: "enterprise:" + enterpriseID,
			AutoUpdate: false, PolicyOrigin: "system-seed", MigrationStatus: "CURRENT", ParanoiaLevel: policyTemplate.Defaults.ParanoiaLevel,
			ExecutingParanoiaLevel: policyTemplate.Defaults.ExecutingParanoiaLevel, InboundScore: policyTemplate.Defaults.InboundScore,
			OutboundScore: policyTemplate.Defaults.OutboundScore, RequestBody: policyTemplate.Defaults.RequestBody,
			ResponseBody: policyTemplate.Defaults.ResponseBody, EarlyBlocking: policyTemplate.Defaults.EarlyBlocking,
			SamplingPercentage: policyTemplate.Defaults.SamplingPercentage,
		}
		revision, fullPath, err := s.preparePolicyRevision(policyTemplate, policyTemplate.Name, policyTemplate.Description, policyTemplate.Defaults.Mode, settings, "", "system-seed")
		if err != nil {
			seedErrors = append(seedErrors, err)
			continue
		}
		serverIDs := orderedRolloutServerIDs(targetServers)
		rolloutID, err := s.store.CreateEnterprisePolicyWithRollout(ctx, enterpriseID, policyID, policyTemplate.Name, policyTemplate.Description, settings.Target, policyTemplate.Key, PolicyStrategyManual, "", revision, "SEED", "QUEUED", serverIDs)
		if err != nil {
			_ = os.Remove(fullPath)
			seedErrors = append(seedErrors, err)
			continue
		}
		s.logger.Info("enterprise_policy_seeded", "enterprise_id", enterpriseID, "enterprise_policy_id", policyID, "rollout_id", rolloutID, "system_policy", policyTemplate.Reference(), "server_count", len(serverIDs))
	}
	return errors.Join(seedErrors...)
}

func (s *Server) prepareAvailablePolicyUpdate(ctx context.Context, policy EnterprisePolicyRecord, serverIDs []string, servers []ServerRecord) error {
	if !policy.HasUpdate() || policy.UpdateStrategy == PolicyStrategyPinned || policy.CurrentRevisionID == "" || len(serverIDs) == 0 || policy.HasActiveRollout || policy.LatestRolloutStatus == "FAILED" {
		return nil
	}
	blocked, err := s.store.PolicyUpdateBlocked(ctx, policy.ID, policy.LatestSystemPolicyID)
	if err != nil {
		return err
	}
	if blocked {
		return nil
	}
	targetTemplate, ok := s.systemPolicyTemplate(ctx, policy.LatestSystemPolicyID)
	if !ok || targetTemplate.Status != systempolicy.StatusPublished {
		return errors.New("latest published system policy is unavailable")
	}
	settings := policy.CurrentSettings
	settings.SchemaVersion = targetTemplate.SchemaVersion
	settings.TemplateKey = targetTemplate.Key
	settings.TemplateVersion = targetTemplate.Version
	settings.CRSTrack = targetTemplate.CRSTrack
	settings.CRSVersion = targetTemplate.CRSVersion
	settings.AutoUpdate = policy.UpdateStrategy == PolicyStrategyAutomatic
	settings.PolicyOrigin = "system-migration"
	settings.MigrationStatus = "READY"
	settings.MigratedFrom = policy.CurrentRevisionID
	if detail := s.changedEnterpriseRuleImpact(ctx, policy.CurrentSystemPolicyID, targetTemplate, settings); detail != "" {
		if err := s.store.SetPolicyMigrationImpact(ctx, policy.ID, targetTemplate.Reference(), detail); err != nil {
			return err
		}
		return nil
	}
	revision, fullPath, err := s.preparePolicyRevision(targetTemplate, policy.Name, policy.Description, policy.CurrentMode, settings, policy.CurrentRevisionID, "system-migration")
	if err != nil {
		var migrationErr PolicyMigrationRequiredError
		if errors.As(err, &migrationErr) {
			if markErr := s.store.SetPolicyMigrationImpact(ctx, policy.ID, targetTemplate.Reference(), migrationErr.Detail); markErr != nil {
				return markErr
			}
			s.logger.Warn("enterprise_policy_migration_required", "enterprise_policy_id", policy.ID, "target", targetTemplate.Reference(), "detail", migrationErr.Detail)
			return nil
		}
		return err
	}
	if err := s.store.ClearPolicyMigrationImpact(ctx, policy.ID, targetTemplate.Reference()); err != nil {
		_ = os.Remove(fullPath)
		return err
	}
	status := "AWAITING_APPROVAL"
	if policy.UpdateStrategy == PolicyStrategyAutomatic {
		status = "QUEUED"
	}
	serverIDs = orderIDsByServers(serverIDs, servers)
	rolloutID, err := s.store.CreatePolicyRollout(ctx, policy, policy.CurrentRevisionID, "UPDATE", status, "", &revision, "", targetTemplate.Reference(), serverIDs)
	if err != nil {
		_ = os.Remove(fullPath)
		if strings.Contains(err.Error(), "active rollout") {
			return nil
		}
		return err
	}
	s.logger.Info("enterprise_policy_update_available", "enterprise_policy_id", policy.ID, "rollout_id", rolloutID, "strategy", policy.UpdateStrategy, "from", policy.CurrentSystemPolicyID, "to", targetTemplate.Reference())
	return nil
}

func (s *Server) changedEnterpriseRuleImpact(ctx context.Context, currentSystemPolicyID string, target systempolicy.Template, settings PolicySettings) string {
	current, ok := s.systemPolicyTemplate(ctx, currentSystemPolicyID)
	if !ok || current.Defaults.CRSSource == nil || target.Defaults.CRSSource == nil {
		return ""
	}
	_, previousIndex, previousOK, previousErr := s.indexedPolicySource(ctx, current.Defaults.CRSSource.ID)
	_, targetIndex, targetOK, targetErr := s.indexedPolicySource(ctx, target.Defaults.CRSSource.ID)
	if previousErr != nil || targetErr != nil || !previousOK || !targetOK {
		return ""
	}
	previous := make(map[int]string, len(previousIndex.Rules))
	for _, rule := range previousIndex.Rules {
		previous[rule.ID] = rule.ContentHash
	}
	changed := make(map[int]bool)
	for _, rule := range targetIndex.Rules {
		if old, exists := previous[rule.ID]; exists && old != rule.ContentHash {
			changed[rule.ID] = true
		}
	}
	for _, exclusion := range settings.Exclusions {
		if (exclusion.Type == PolicyExclusionRule || exclusion.Type == PolicyExclusionTarget) && changed[exclusion.RuleID] {
			return fmt.Sprintf("내용이 변경된 CRS Rule %d을 기업 예외가 참조하여 수동 검토가 필요합니다", exclusion.RuleID)
		}
	}
	return ""
}

func (s *Server) processPolicyRollout(ctx context.Context, rollout PolicyRolloutRecord) error {
	targetTemplate, ok := s.systemPolicyTemplate(ctx, rollout.TargetSystemPolicyVersionID)
	if !ok {
		_ = s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "FAILED", "시스템 정책 버전을 찾을 수 없습니다.")
		return errors.New("target system policy version is unavailable")
	}
	if targetTemplate.Status == systempolicy.StatusWithdrawn {
		_ = s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "FAILED", "회수된 시스템 정책 버전은 적용하거나 롤백할 수 없습니다.")
		return errors.New("target system policy version is withdrawn")
	}
	targets, err := s.store.ListPolicyRolloutTargets(ctx, rollout.ID)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target.Status == "FAILED" {
			return s.handleRolloutFailure(ctx, rollout, targets, target.Detail)
		}
	}
	for index := range targets {
		target := &targets[index]
		if target.Status == "DEFERRED" && target.Online {
			resumeStatus := target.ResumeStatus
			if resumeStatus == "" {
				resumeStatus = "PENDING"
			}
			if err := s.store.ResumePolicyRolloutTarget(ctx, rollout.ID, target.ServerID, resumeStatus); err != nil {
				return err
			}
			target.Status = resumeStatus
			target.ResumeStatus = ""
		} else if target.Status != "DEFERRED" && target.Status != "APPLIED" && target.Status != "ROLLED_BACK" && target.Status != "FAILED" && !target.Online {
			if err := s.store.DeferPolicyRolloutTarget(ctx, rollout.ID, target.ServerID, target.Status); err != nil {
				return err
			}
			target.ResumeStatus = target.Status
			target.Status = "DEFERRED"
		}
	}
	var deferredCanary *PolicyRolloutTargetRecord
	var appliedCanary *PolicyRolloutTargetRecord
	canaryApplied := false
	for index := range targets {
		target := &targets[index]
		if target.BatchNo != 0 {
			continue
		}
		if target.Status == "APPLIED" || target.Status == "ROLLED_BACK" {
			canaryApplied = true
			if target.Status == "APPLIED" {
				appliedCanary = target
			}
		}
		if target.Status == "DEFERRED" {
			deferredCanary = target
		}
	}
	if !canaryApplied && deferredCanary != nil {
		for index := range targets {
			candidate := &targets[index]
			if candidate.BatchNo > 0 && candidate.Status == "PENDING" && candidate.Online {
				replacementBatch := candidate.BatchNo
				if err := s.store.SwapPolicyRolloutCanary(ctx, rollout.ID, deferredCanary.ServerID, candidate.ServerID, replacementBatch); err != nil {
					return err
				}
				deferredCanary.BatchNo = replacementBatch
				candidate.BatchNo = 0
				break
			}
		}
	}
	if rollout.Type == "UPDATE" && rollout.FromRevisionID != "" && rollout.Status == "CANARY" && appliedCanary != nil && hasPendingExpansionTargets(targets) {
		ready, failure, err := s.evaluateCanaryGate(ctx, rollout, targetTemplate, *appliedCanary)
		if err != nil {
			return err
		}
		if !ready {
			return nil
		}
		if failure != "" {
			return s.recoverFailedCanary(ctx, rollout, *appliedCanary, failure)
		}
		_ = s.store.Audit(ctx, randomID(), "system:policy-rollout", "policy_rollout.canary_gate", rollout.ID+":"+appliedCanary.ServerID, "success", "internal")
	}
	currentBatch := -1
	for _, target := range targets {
		if target.Status == "APPLIED" || target.Status == "ROLLED_BACK" || target.Status == "DEFERRED" {
			continue
		}
		if currentBatch == -1 || target.BatchNo < currentBatch {
			currentBatch = target.BatchNo
		}
	}
	if currentBatch == -1 {
		allDone := true
		for _, target := range targets {
			if target.Status == "DEFERRED" {
				allDone = false
				break
			}
		}
		if allDone {
			return s.store.CompletePolicyRollout(ctx, rollout)
		}
		return nil
	}
	rolloutStatus := "CANARY"
	if currentBatch > 0 {
		rolloutStatus = "EXPANDING"
	}
	if rollout.Status != rolloutStatus {
		if err := s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, rolloutStatus, ""); err != nil {
			return err
		}
	}
	transitionRevisionID := existingTransitionRevision(targets)
	for _, target := range targets {
		if target.BatchNo != currentBatch || target.Status == "APPLIED" || target.Status == "ROLLED_BACK" {
			continue
		}
		if !target.Online {
			continue
		}
		if err := s.advanceRolloutTarget(ctx, rollout, targetTemplate, &transitionRevisionID, target); err != nil {
			_ = s.store.UpdatePolicyRolloutTarget(ctx, rollout.ID, target.ServerID, "FAILED", truncate(err.Error(), 4096))
			updatedTargets, loadErr := s.store.ListPolicyRolloutTargets(ctx, rollout.ID)
			if loadErr != nil {
				return errors.Join(err, loadErr)
			}
			return s.handleRolloutFailure(ctx, rollout, updatedTargets, err.Error())
		}
	}
	return nil
}

func hasPendingExpansionTargets(targets []PolicyRolloutTargetRecord) bool {
	for _, target := range targets {
		if target.BatchNo > 0 && target.Status != "APPLIED" && target.Status != "ROLLED_BACK" {
			return true
		}
	}
	return false
}

func (s *Server) evaluateCanaryGate(ctx context.Context, rollout PolicyRolloutRecord, targetTemplate systempolicy.Template, canary PolicyRolloutTargetRecord) (bool, string, error) {
	if !canary.StabilizedAt.Valid {
		return false, "", nil
	}
	observationStart := canary.StabilizedAt.Time.UTC()
	observationEnd := observationStart.Add(10 * time.Minute)
	if time.Now().UTC().Before(observationEnd) {
		return false, "", nil
	}
	if !canary.Online {
		return true, "카나리 관찰 종료 시 최근 heartbeat가 없습니다.", nil
	}
	if normalizeCRSVersion(canary.InventoryCRSVersion) != normalizeCRSVersion(targetTemplate.CRSVersion) {
		return true, "카나리의 실제 CRS 버전이 대상 시스템 정책과 다릅니다.", nil
	}
	if canary.CurrentPolicyRevision != canary.FinalRevisionID || canary.PolicyStatus != "APPLIED" {
		return true, "카나리의 실제 정책 revision을 확인할 수 없습니다.", nil
	}
	baseline, err := s.store.CountBlockedEvents(ctx, canary.ServerID, observationStart.Add(-60*time.Minute), observationStart, "")
	if err != nil {
		return false, "", err
	}
	observed, err := s.store.CountBlockedEvents(ctx, canary.ServerID, observationStart, observationEnd, canary.FinalRevisionID)
	if err != nil {
		return false, "", err
	}
	baselineRate := float64(baseline) / 60
	observedRate := float64(observed) / 10
	threshold := math.Max(5, baselineRate*3)
	if observedRate > threshold {
		return true, fmt.Sprintf("카나리 차단률이 %.2f건/분으로 허용 기준 %.2f건/분을 초과했습니다. 기준선은 %.2f건/분입니다.", observedRate, threshold, baselineRate), nil
	}
	return true, "", nil
}

func (s *Server) recoverFailedCanary(ctx context.Context, rollout PolicyRolloutRecord, canary PolicyRolloutTargetRecord, detail string) error {
	_ = s.store.Audit(ctx, randomID(), "system:policy-rollout", "policy_rollout.canary_gate", rollout.ID+":"+canary.ServerID+":"+truncate(detail, 512), "failed", "internal")
	if err := s.store.UpdatePolicyRolloutTarget(ctx, rollout.ID, canary.ServerID, "FAILED", truncate(detail, 4096)); err != nil {
		return err
	}
	if err := s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "FAILED", truncate(detail, 4096)); err != nil {
		return err
	}
	policy, err := s.store.EnterprisePolicyByID(ctx, rollout.EnterpriseID, rollout.EnterprisePolicyID)
	if err != nil {
		return err
	}
	fromRevision, err := s.store.PolicyRevisionByID(ctx, rollout.EnterprisePolicyID, rollout.FromRevisionID)
	if err != nil {
		return err
	}
	_, err = s.store.CreatePolicyRollout(ctx, policy, policy.CurrentRevisionID, "RECOVERY", "QUEUED", "", nil, fromRevision.ID, fromRevision.SystemPolicyVersionID, []string{canary.ServerID})
	result := "success"
	if err != nil {
		result = "failed"
	}
	_ = s.store.Audit(ctx, randomID(), "system:policy-rollout", "policy_rollout.canary_recovery", rollout.ID+":"+canary.ServerID+":"+truncate(detail, 512), result, "internal")
	return err
}

func (s *Server) advanceRolloutTarget(ctx context.Context, rollout PolicyRolloutRecord, targetTemplate systempolicy.Template, transitionRevisionID *string, target PolicyRolloutTargetRecord) error {
	switch target.Status {
	case "PENDING", "DEFERRED":
		needsV2Package, err := s.rolloutNeedsV2Package(ctx, rollout, targetTemplate)
		if err != nil {
			return err
		}
		if targetTemplate.Defaults.ArtifactFormat == policybundle.FormatV3 || normalizeCRSVersion(target.InventoryCRSVersion) == normalizeCRSVersion(targetTemplate.CRSVersion) && !needsV2Package {
			return s.store.AssignPolicyForRollout(ctx, rollout.ID, rollout.EnterpriseID, target.ServerID, target.FinalRevisionID, "", "POLICY_PENDING")
		}
		if rollout.FromRevisionID != "" {
			if *transitionRevisionID == "" {
				policy, err := s.store.EnterprisePolicyByID(ctx, rollout.EnterpriseID, rollout.EnterprisePolicyID)
				if err != nil {
					return err
				}
				revision, fullPath, err := s.prepareTransitionRevision(targetTemplate, policy, rollout.FromRevisionID)
				if err != nil {
					return err
				}
				if err := s.store.InsertPolicyRevision(ctx, rollout.EnterpriseID, rollout.EnterprisePolicyID, revision); err != nil {
					_ = os.Remove(fullPath)
					return err
				}
				*transitionRevisionID = revision.ID
			}
			return s.store.AssignPolicyForRollout(ctx, rollout.ID, rollout.EnterpriseID, target.ServerID, *transitionRevisionID, "", "TRANSITION_PENDING")
		}
		return s.queueRolloutPackage(ctx, rollout, targetTemplate, target)
	case "TRANSITION_PENDING":
		if target.TransitionPolicyStatus == "FAILED" {
			return errors.New("DetectionOnly 전환 정책 적용에 실패했습니다.")
		}
		if target.CurrentPolicyRevision == target.TransitionRevisionID && target.TransitionPolicyStatus == "APPLIED" {
			return s.queueRolloutPackage(ctx, rollout, targetTemplate, target)
		}
	case "PACKAGE_PENDING", "ROLLBACK_PENDING":
		if target.PackageStatus == "FAILED" {
			return errors.New("CRS 패키지 적용에 실패했습니다.")
		}
		if target.PackageStatus == "APPLIED" && normalizeCRSVersion(target.InventoryCRSVersion) == normalizeCRSVersion(targetTemplate.CRSVersion) {
			return s.store.AssignPolicyForRollout(ctx, rollout.ID, rollout.EnterpriseID, target.ServerID, target.FinalRevisionID, "", "POLICY_PENDING")
		}
	case "POLICY_PENDING":
		if target.PolicyStatus == "FAILED" {
			return errors.New("최종 기업 정책 적용에 실패했습니다.")
		}
		if target.PolicyStatus == "APPLIED" && target.CurrentPolicyRevision == target.FinalRevisionID {
			return s.store.UpdatePolicyRolloutTarget(ctx, rollout.ID, target.ServerID, "APPLIED", "")
		}
	}
	return nil
}

func (s *Server) rolloutNeedsV2Package(ctx context.Context, rollout PolicyRolloutRecord, target systempolicy.Template) (bool, error) {
	if target.Defaults.ArtifactFormat != policybundle.Format {
		return false, nil
	}
	if rollout.FromRevisionID == "" {
		return true, nil
	}
	from, err := s.store.PolicyRevisionByID(ctx, rollout.EnterprisePolicyID, rollout.FromRevisionID)
	if err != nil {
		return false, err
	}
	base, ok := s.systemPolicyTemplate(ctx, from.SystemPolicyVersionID)
	return !ok || base.Defaults.ArtifactFormat != policybundle.Format, nil
}

func (s *Server) queueRolloutPackage(ctx context.Context, rollout PolicyRolloutRecord, targetTemplate systempolicy.Template, target PolicyRolloutTargetRecord) error {
	if s.catalog == nil {
		return errors.New("서명 패키지 catalog를 사용할 수 없습니다.")
	}
	server, err := s.store.ServerByID(ctx, rollout.EnterpriseID, target.ServerID)
	if err != nil {
		return err
	}
	if server.Inventory.InstallationMode == "manual" {
		return errors.New("수동 Connector 서버에는 legacy CRS 모듈 패키지를 배포할 수 없습니다.")
	}
	agentPackage, modulePackage, err := s.catalog.ResolveCRS(server.Inventory, targetTemplate.CRSVersion)
	if err != nil {
		return err
	}
	targetStatus := "PACKAGE_PENDING"
	if rollout.Type == "ROLLBACK" || rollout.Type == "RECOVERY" {
		targetStatus = "ROLLBACK_PENDING"
	}
	_, err = s.store.AssignPackagesForRollout(ctx, rollout.ID, rollout.EnterpriseID, target.ServerID, agentPackage.ID, modulePackage.ID, "", targetStatus)
	return err
}

func (s *Server) handleRolloutFailure(ctx context.Context, rollout PolicyRolloutRecord, targets []PolicyRolloutTargetRecord, detail string) error {
	policy, err := s.store.EnterprisePolicyByID(ctx, rollout.EnterpriseID, rollout.EnterprisePolicyID)
	if err != nil {
		return err
	}
	if rollout.Type == "UPDATE" && rollout.FromRevisionID != "" {
		for _, target := range targets {
			if target.BatchNo == 0 && target.Status == "FAILED" && rolloutTargetChanged(target) {
				return s.recoverFailedCanary(ctx, rollout, target, detail)
			}
		}
	}
	if rollout.Type != "UPDATE" || policy.UpdateStrategy != PolicyStrategyAutomatic || rollout.FromRevisionID == "" {
		return s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "PAUSED", truncate(detail, 4096))
	}
	recoveryServers := make([]string, 0)
	for _, target := range targets {
		if target.Status != "PENDING" && target.Status != "DEFERRED" && (target.Status != "FAILED" || rolloutTargetChanged(target)) {
			recoveryServers = append(recoveryServers, target.ServerID)
		}
	}
	if len(recoveryServers) == 0 {
		return s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "PAUSED", truncate(detail, 4096))
	}
	if err := s.store.UpdatePolicyRolloutStatus(ctx, rollout.ID, "FAILED", truncate(detail, 4096)); err != nil {
		return err
	}
	fromRevision, err := s.store.PolicyRevisionByID(ctx, rollout.EnterprisePolicyID, rollout.FromRevisionID)
	if err != nil {
		return err
	}
	_, err = s.store.CreatePolicyRollout(ctx, policy, policy.CurrentRevisionID, "RECOVERY", "QUEUED", "", nil, fromRevision.ID, fromRevision.SystemPolicyVersionID, recoveryServers)
	return err
}

func rolloutTargetChanged(target PolicyRolloutTargetRecord) bool {
	return target.TransitionRevisionID != "" || target.PackageDeploymentID != "" || target.DesiredPolicyRevision == target.FinalRevisionID && target.FinalRevisionID != ""
}

func (s *Server) preparePolicyRevision(policyTemplate systempolicy.Template, name, description, mode string, settings PolicySettings, parentRevisionID, origin string) (PolicyRevisionInput, string, error) {
	revisionID := randomID()
	metadata := ManagedPolicyMetadata{
		SchemaVersion: settings.SchemaVersion, TemplateKey: settings.TemplateKey, TemplateVersion: settings.TemplateVersion,
		CRSTrack: settings.CRSTrack, CRSVersion: settings.CRSVersion, Target: settings.Target, AutoUpdate: settings.AutoUpdate,
		PolicyOrigin: settings.PolicyOrigin, MigrationStatus: settings.MigrationStatus, MigratedFrom: parentRevisionID,
	}
	artifact, settingsJSON, err := buildEnterprisePolicyArtifact(policyTemplate, mode, settings.ParanoiaLevel, settings.InboundScore, settings.RequestBody, strings.Join(settings.ExcludedPaths, "\n"), strings.Join(settings.ExcludedIPs, "\n"), settings.CustomRules, metadata)
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	var normalized PolicySettings
	if err := json.Unmarshal([]byte(settingsJSON), &normalized); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	normalized.ExecutingParanoiaLevel = settings.ExecutingParanoiaLevel
	normalized.OutboundScore = settings.OutboundScore
	normalized.ResponseBody = settings.ResponseBody
	normalized.EarlyBlocking = settings.EarlyBlocking
	normalized.SamplingPercentage = settings.SamplingPercentage
	normalized.LegacyPolicyConfirmed = settings.LegacyPolicyConfirmed
	normalized.Exclusions = append([]PolicyExclusion(nil), settings.Exclusions...)
	configuration, legacy, err := structuredConfigurationFromPolicy("", revisionID, policyTemplate, mode, normalized)
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	for _, rule := range configuration.CustomRules {
		if rule.LegacyIDRange {
			return PolicyRevisionInput{}, "", PolicyMigrationRequiredError{Detail: fmt.Sprintf("legacy Rule ID %d를 현재 %s ID 범위로 변경해야 새 개정본을 만들 수 있습니다", rule.RuleID, rule.SourceScope)}
		}
	}
	if legacy {
		if origin == "administrator" || origin == "system-migration" && !settings.LegacyPolicyConfirmed {
			return PolicyRevisionInput{}, "", PolicyMigrationRequiredError{Detail: "legacy 전체 엔진 우회를 Rule·Target·Tag 예외로 전환하거나 명시적으로 유지 확인해야 합니다"}
		}
	}
	normalized.ParanoiaLevel = configuration.BlockingParanoiaLevel
	normalized.ExecutingParanoiaLevel = configuration.ExecutingParanoiaLevel
	normalized.InboundScore = configuration.InboundAnomalyThreshold
	normalized.OutboundScore = configuration.OutboundAnomalyThreshold
	normalized.RequestBody = configuration.RequestBodyAccess
	normalized.ResponseBody = configuration.ResponseBodyAccess
	normalized.EarlyBlocking = configuration.EarlyBlocking
	normalized.SamplingPercentage = configuration.SamplingPercentage
	if !legacy || origin == "system-migration" {
		// An unused acknowledgement is cleared, and a used acknowledgement is
		// consumed by one migration so a later CRS update requires review again.
		normalized.LegacyPolicyConfirmed = false
	}
	settingsRaw, err := json.Marshal(normalized)
	if err != nil {
		return PolicyRevisionInput{}, "", err
	}
	settingsJSON = string(settingsRaw)
	extension := ".conf"
	if policyTemplate.Defaults.ArtifactFormat == policybundle.Format || policyTemplate.Defaults.ArtifactFormat == policybundle.FormatV3 {
		if policyTemplate.Defaults.CRSSource == nil {
			return PolicyRevisionInput{}, "", errors.New("policy bundle requires a verified CRS source")
		}
		normalized.ArtifactFormat = policyTemplate.Defaults.ArtifactFormat
		settingsRaw, err = json.Marshal(normalized)
		if err != nil {
			return PolicyRevisionInput{}, "", err
		}
		settingsJSON = string(settingsRaw)
		_, sourceIndex, ok, indexErr := s.indexedPolicySource(context.Background(), configuration.CRSReleaseID)
		if indexErr != nil {
			return PolicyRevisionInput{}, "", indexErr
		}
		if !ok {
			return PolicyRevisionInput{}, "", errors.New("verified CRS source index is unavailable")
		}
		if err := validateConfigurationRuleIDs(configuration, sourceIndex); err != nil {
			return PolicyRevisionInput{}, "", err
		}
		bundleInput := policyBundleInputFromConfiguration(configuration)
		if policyTemplate.Defaults.ArtifactFormat == policybundle.FormatV3 {
			files, filesErr := s.policySourceFiles(policyTemplate.Defaults.CRSSource.ID)
			if filesErr != nil {
				return PolicyRevisionInput{}, "", filesErr
			}
			artifact, _, err = policybundle.BuildWithCRS(*policyTemplate.Defaults.CRSSource, bundleInput, files)
		} else {
			artifact, _, err = policybundle.Build(*policyTemplate.Defaults.CRSSource, bundleInput)
		}
		if err != nil {
			return PolicyRevisionInput{}, "", err
		}
		extension = ".tar.gz"
		if policyTemplate.Defaults.ArtifactFormat == policybundle.FormatV3 {
			extension = ".v3.tar.gz"
		}
	}
	hash, signature := s.policySigner.Sign(artifact)
	relativePath := filepath.Join("policies", revisionID+extension)
	fullPath := filepath.Join(s.cfg.ArtifactRoot, relativePath)
	if err := writeArtifact(fullPath, artifact); err != nil {
		return PolicyRevisionInput{}, "", err
	}
	return PolicyRevisionInput{
		ID: revisionID, SystemPolicyVersionID: policyTemplate.Reference(), ParentRevisionID: parentRevisionID,
		Name: truncate(name, 255), Description: truncate(description, 1024), Mode: mode, SettingsJSON: settingsJSON,
		ArtifactPath: filepath.ToSlash(relativePath), ArtifactSHA256: hash, ArtifactSignature: signature, PolicyOrigin: origin, Configuration: &configuration,
	}, fullPath, nil
}

func policyBundleInputFromConfiguration(configuration PolicyConfiguration) policybundle.Input {
	input := policybundle.Input{
		Mode: configuration.EngineMode, RequestBody: configuration.RequestBodyAccess, ResponseBody: configuration.ResponseBodyAccess,
		CRSSetup: configuration.CRSSetupMap(),
	}
	for _, item := range configuration.Exclusions {
		exclusion := policybundle.Exclusion{
			Type: item.Type, LoadStage: item.LoadStage, RuleID: item.RuleID, RuleTag: item.RuleTag, Target: item.Target,
			GeneratedRuleID: item.GeneratedRuleID, Enabled: item.Enabled,
		}
		for _, condition := range item.Conditions {
			exclusion.Conditions = append(exclusion.Conditions, policybundle.Condition{Field: condition.Field, Operator: condition.Operator, Value: condition.Value})
		}
		input.Exclusions = append(input.Exclusions, exclusion)
	}
	for _, item := range configuration.CustomRules {
		input.CustomRules = append(input.CustomRules, policybundle.CustomRule{RuleID: item.RuleID, Scope: item.SourceScope, Canonical: item.CanonicalSecRule, Enabled: item.Enabled})
	}
	return input
}

func (s *Server) prepareTransitionRevision(target systempolicy.Template, policy EnterprisePolicyRecord, parentRevisionID string) (PolicyRevisionInput, string, error) {
	settings := PolicySettings{
		SchemaVersion: target.SchemaVersion, TemplateKey: target.Key, TemplateVersion: target.Version, CRSTrack: target.CRSTrack,
		CRSVersion: target.CRSVersion, Target: policy.Target, PolicyOrigin: "system-transition", MigrationStatus: "TRANSITION",
		ParanoiaLevel: 1, ExecutingParanoiaLevel: 1, InboundScore: 5, OutboundScore: 4, RequestBody: true, SamplingPercentage: 100,
	}
	legacyTarget := target
	legacyTarget.Defaults.ArtifactFormat = ""
	legacyTarget.Defaults.CRSSource = nil
	return s.preparePolicyRevision(legacyTarget, policy.Name+" 전환 보호", "CRS 변경 중 사용하는 최소 DetectionOnly 정책", "DetectionOnly", settings, parentRevisionID, "system-transition")
}

func (s *Server) enterprisePolicyWinners(ctx context.Context, policies []EnterprisePolicyRecord, servers []ServerRecord) (map[string][]string, error) {
	type winner struct {
		policy   EnterprisePolicyRecord
		priority int
	}
	serverByID := make(map[string]ServerRecord, len(servers))
	for _, server := range servers {
		if !server.Revoked {
			serverByID[server.ID] = server
		}
	}
	winners := make(map[string]winner)
	for _, policy := range policies {
		if policy.Status != EnterprisePolicyActive || policy.CurrentRevisionID == "" {
			continue
		}
		ids, priority, err := s.resolveEnterprisePolicyTarget(ctx, policy, servers)
		if err != nil {
			continue
		}
		for _, serverID := range ids {
			server, ok := serverByID[serverID]
			if !ok || server.EnterpriseID != policy.EnterpriseID {
				continue
			}
			current, exists := winners[serverID]
			if !exists || priority > current.priority || priority == current.priority && policy.UpdatedAt.After(current.policy.UpdatedAt) {
				winners[serverID] = winner{policy: policy, priority: priority}
			}
		}
	}
	result := make(map[string][]string)
	for serverID, winner := range winners {
		result[winner.policy.ID] = append(result[winner.policy.ID], serverID)
	}
	for policyID := range result {
		sort.Strings(result[policyID])
	}
	return result, nil
}

func (s *Server) resolveEnterprisePolicyTarget(ctx context.Context, policy EnterprisePolicyRecord, servers []ServerRecord) ([]string, int, error) {
	kind, id, ok := strings.Cut(policy.Target, ":")
	if !ok || id == "" {
		return nil, 0, errors.New("invalid enterprise policy target")
	}
	if kind == "enterprise" {
		if id != policy.EnterpriseID {
			return nil, 0, errors.New("enterprise target mismatch")
		}
		ids := make([]string, 0)
		for _, server := range servers {
			if !server.Revoked && server.EnterpriseID == policy.EnterpriseID {
				ids = append(ids, server.ID)
			}
		}
		return ids, 1, nil
	}
	enterpriseID, ids, err := s.store.ResolvePolicyTarget(ctx, policy.EnterpriseID, policy.Target)
	if err != nil {
		return nil, 0, err
	}
	if enterpriseID != policy.EnterpriseID {
		return nil, 0, errors.New("resolved enterprise target mismatch")
	}
	priority := 2
	if kind == "server" {
		priority = 3
	}
	return ids, priority, nil
}

func (s *Server) reconcileEnterprisePolicyMembership(ctx context.Context, policies []EnterprisePolicyRecord, winners map[string][]string, servers []ServerRecord) error {
	revisionOwners := make(map[string]string)
	policyByID := make(map[string]EnterprisePolicyRecord)
	for _, policy := range policies {
		policyByID[policy.ID] = policy
		if policy.CurrentRevisionID != "" {
			revisionOwners[policy.CurrentRevisionID] = policy.ID
		}
	}
	serverByID := make(map[string]ServerRecord, len(servers))
	for _, server := range servers {
		serverByID[server.ID] = server
	}
	var reconcileErrors []error
	for policyID, serverIDs := range winners {
		policy := policyByID[policyID]
		eligible := make([]string, 0)
		for _, serverID := range serverIDs {
			server := serverByID[serverID]
			if server.DesiredPolicyRevision == policy.CurrentRevisionID {
				continue
			}
			if server.DesiredPolicyRevision != "" {
				if _, managed := revisionOwners[server.DesiredPolicyRevision]; !managed {
					continue
				}
			}
			eligible = append(eligible, serverID)
		}
		if len(eligible) != 0 {
			if err := s.store.AssignExistingPolicyToServers(ctx, policy.EnterpriseID, eligible, policy.CurrentRevisionID, ""); err != nil {
				reconcileErrors = append(reconcileErrors, err)
			}
		}
	}
	return errors.Join(reconcileErrors...)
}

func splitSystemPolicyReference(catalog *systempolicy.Catalog, reference string) (systempolicy.Template, bool) {
	key, versionText, ok := strings.Cut(reference, "@")
	if !ok {
		return systempolicy.Template{}, false
	}
	return catalog.Version(key, versionText)
}

func existingTransitionRevision(targets []PolicyRolloutTargetRecord) string {
	for _, target := range targets {
		if target.TransitionRevisionID != "" {
			return target.TransitionRevisionID
		}
	}
	return ""
}

func orderedRolloutServerIDs(servers []ServerRecord) []string {
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Status == "ONLINE" && servers[j].Status != "ONLINE" {
			return true
		}
		if servers[i].Status != "ONLINE" && servers[j].Status == "ONLINE" {
			return false
		}
		return servers[i].Name < servers[j].Name
	})
	ids := make([]string, 0, len(servers))
	for _, server := range servers {
		ids = append(ids, server.ID)
	}
	return ids
}

func orderIDsByServers(ids []string, servers []ServerRecord) []string {
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	selected := make([]ServerRecord, 0, len(ids))
	for _, server := range servers {
		if allowed[server.ID] {
			selected = append(selected, server)
		}
	}
	return orderedRolloutServerIDs(selected)
}

func normalizeCRSVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}
