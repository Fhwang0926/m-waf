package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const systemPolicyServerLimit = 5000

type policyWinner struct {
	binding  ManagedPolicyRecord
	priority int
}

// SyncSystemPolicies creates the missing enterprise baseline and reconciles
// auto-updating policy bindings with the embedded, reviewed template catalog.
// A policy chosen explicitly outside this catalog is treated as a per-server
// lock and is never overwritten by the controller.
func (s *Server) SyncSystemPolicies(ctx context.Context) error {
	s.policySyncMu.Lock()
	defer s.policySyncMu.Unlock()

	servers, err := s.store.ListServers(ctx, "", systemPolicyServerLimit)
	if err != nil {
		return fmt.Errorf("list servers for system policy sync: %w", err)
	}
	bindings, err := s.store.ListManagedPolicyBindings(ctx)
	if err != nil {
		return fmt.Errorf("list managed policy bindings: %w", err)
	}
	seeded, seedErr := s.seedEnterprisePolicies(ctx, servers, bindings)
	if seeded {
		servers, err = s.store.ListServers(ctx, "", systemPolicyServerLimit)
		if err != nil {
			return errors.Join(seedErr, fmt.Errorf("reload servers after policy seed: %w", err))
		}
		bindings, err = s.store.ListManagedPolicyBindings(ctx)
		if err != nil {
			return errors.Join(seedErr, fmt.Errorf("reload managed policies after seed: %w", err))
		}
	}

	serverByID := make(map[string]ServerRecord, len(servers))
	managedIDs := make(map[string]bool, len(bindings))
	for _, server := range servers {
		if !server.Revoked {
			serverByID[server.ID] = server
		}
	}
	for _, binding := range bindings {
		managedIDs[binding.ID] = true
	}

	winners := make(map[string]policyWinner)
	var syncErrors []error
	if seedErr != nil {
		syncErrors = append(syncErrors, seedErr)
	}
	for _, binding := range bindings {
		serverIDs, priority, err := s.resolveManagedPolicyTarget(ctx, binding, serverByID)
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("resolve managed policy %s: %w", binding.ID, err))
			continue
		}
		for _, serverID := range serverIDs {
			server, ok := serverByID[serverID]
			if !ok || server.EnterpriseID != binding.EnterpriseID {
				continue
			}
			if server.DesiredPolicyRevision != "" && !managedIDs[server.DesiredPolicyRevision] {
				continue
			}
			current, exists := winners[serverID]
			if !exists || priority > current.priority || priority == current.priority && binding.CreatedAt.After(current.binding.CreatedAt) {
				winners[serverID] = policyWinner{binding: binding, priority: priority}
			}
		}
	}

	targetsByBinding := make(map[string][]string)
	bindingByID := make(map[string]ManagedPolicyRecord, len(bindings))
	for _, binding := range bindings {
		bindingByID[binding.ID] = binding
	}
	for serverID, winner := range winners {
		targetsByBinding[winner.binding.ID] = append(targetsByBinding[winner.binding.ID], serverID)
	}
	for bindingID, serverIDs := range targetsByBinding {
		sort.Strings(serverIDs)
		if err := s.reconcileManagedPolicy(ctx, bindingByID[bindingID], serverIDs, serverByID); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("reconcile managed policy %s: %w", bindingID, err))
		}
	}
	return errors.Join(syncErrors...)
}

func (s *Server) seedEnterprisePolicies(ctx context.Context, servers []ServerRecord, bindings []ManagedPolicyRecord) (bool, error) {
	hasEnterpriseBinding := make(map[string]bool)
	for _, binding := range bindings {
		kind, id, ok := strings.Cut(binding.Settings.Target, ":")
		if ok && kind == "enterprise" && id == binding.EnterpriseID {
			hasEnterpriseBinding[binding.EnterpriseID] = true
		}
	}
	unassigned := make(map[string][]string)
	for _, server := range servers {
		if !server.Revoked && server.EnterpriseID != "" && server.DesiredPolicyRevision == "" && !hasEnterpriseBinding[server.EnterpriseID] {
			unassigned[server.EnterpriseID] = append(unassigned[server.EnterpriseID], server.ID)
		}
	}

	policyTemplate := s.policyCatalog.Default()
	var seedErrors []error
	seeded := false
	for enterpriseID, serverIDs := range unassigned {
		sort.Strings(serverIDs)
		settings := PolicySettings{
			SchemaVersion: policyTemplate.SchemaVersion, TemplateKey: policyTemplate.Key, TemplateVersion: policyTemplate.Version,
			CRSTrack: policyTemplate.CRSTrack, CRSVersion: policyTemplate.CRSVersion, Target: "enterprise:" + enterpriseID,
			AutoUpdate: true, PolicyOrigin: "system-seed", MigrationStatus: "CURRENT", ParanoiaLevel: policyTemplate.Defaults.ParanoiaLevel,
			InboundScore: policyTemplate.Defaults.InboundScore, RequestBody: policyTemplate.Defaults.RequestBody,
		}
		if _, err := s.createManagedPolicyRevision(ctx, enterpriseID, serverIDs, policyTemplate.Name, policyTemplate.Description, policyTemplate.Defaults.Mode, settings, ""); err != nil {
			seedErrors = append(seedErrors, fmt.Errorf("seed enterprise %s: %w", enterpriseID, err))
			continue
		}
		seeded = true
		s.logger.Info("system_policy_seeded", "enterprise_id", enterpriseID, "template", policyTemplate.Reference(), "crs_version", policyTemplate.CRSVersion, "server_count", len(serverIDs))
	}
	return seeded, errors.Join(seedErrors...)
}

func (s *Server) resolveManagedPolicyTarget(ctx context.Context, binding ManagedPolicyRecord, servers map[string]ServerRecord) ([]string, int, error) {
	kind, id, ok := strings.Cut(binding.Settings.Target, ":")
	if !ok || id == "" {
		return nil, 0, errors.New("invalid managed policy target")
	}
	switch kind {
	case "enterprise":
		if id != binding.EnterpriseID {
			return nil, 0, errors.New("enterprise target does not match policy owner")
		}
		serverIDs := make([]string, 0)
		for _, server := range servers {
			if server.EnterpriseID == binding.EnterpriseID {
				serverIDs = append(serverIDs, server.ID)
			}
		}
		return serverIDs, 1, nil
	case "group", "server":
		enterpriseID, serverIDs, err := s.store.ResolvePolicyTarget(ctx, binding.EnterpriseID, binding.Settings.Target)
		if err != nil {
			return nil, 0, err
		}
		if enterpriseID != binding.EnterpriseID {
			return nil, 0, errors.New("resolved target does not match policy owner")
		}
		priority := 2
		if kind == "server" {
			priority = 3
		}
		return serverIDs, priority, nil
	default:
		return nil, 0, errors.New("unsupported managed policy target")
	}
}

func (s *Server) reconcileManagedPolicy(ctx context.Context, binding ManagedPolicyRecord, serverIDs []string, servers map[string]ServerRecord) error {
	if len(serverIDs) == 0 {
		return nil
	}
	policyTemplate, ok := s.policyCatalog.Latest(binding.Settings.TemplateKey)
	if !ok {
		return fmt.Errorf("template %q is unavailable", binding.Settings.TemplateKey)
	}
	readyServerIDs, packageErr := s.ensureCRSPackages(ctx, binding, policyTemplate, serverIDs, servers)
	if len(readyServerIDs) == 0 {
		return packageErr
	}
	if binding.Settings.SchemaVersion == policyTemplate.SchemaVersion &&
		binding.Settings.TemplateVersion == policyTemplate.Version &&
		normalizeCRSVersion(binding.Settings.CRSVersion) == normalizeCRSVersion(policyTemplate.CRSVersion) {
		return errors.Join(packageErr, s.store.AssignExistingPolicyToServers(ctx, binding.EnterpriseID, readyServerIDs, binding.ID, ""))
	}

	plan := systempolicy.PlanMigration(binding.Settings.SchemaVersion, binding.Settings.TemplateVersion, binding.Settings.CRSVersion, policyTemplate)
	if plan.Status != "READY" {
		return fmt.Errorf("migration status is %s", plan.Status)
	}
	settings := binding.Settings
	settings.SchemaVersion = policyTemplate.SchemaVersion
	settings.TemplateVersion = policyTemplate.Version
	settings.CRSTrack = policyTemplate.CRSTrack
	settings.CRSVersion = policyTemplate.CRSVersion
	settings.PolicyOrigin = "system-migration"
	settings.MigrationStatus = "MIGRATED"
	settings.MigratedFrom = binding.ID
	revisionID, err := s.createManagedPolicyRevision(ctx, binding.EnterpriseID, readyServerIDs, binding.Name, binding.Description, binding.Mode, settings, binding.ID)
	if err != nil {
		return errors.Join(packageErr, err)
	}
	s.logger.Info("system_policy_migrated", "enterprise_id", binding.EnterpriseID, "from_revision", binding.ID, "to_revision", revisionID, "template", policyTemplate.Reference(), "crs_version", policyTemplate.CRSVersion, "changes", plan.Changes, "warnings", plan.Warnings, "server_count", len(readyServerIDs))
	return packageErr
}

func (s *Server) ensureCRSPackages(ctx context.Context, binding ManagedPolicyRecord, policyTemplate systempolicy.Template, serverIDs []string, servers map[string]ServerRecord) ([]string, error) {
	readyServerIDs := make([]string, 0, len(serverIDs))
	var packageErrors []error
	for _, serverID := range serverIDs {
		server, ok := servers[serverID]
		if !ok {
			continue
		}
		if normalizeCRSVersion(server.Inventory.CRSVersion) == normalizeCRSVersion(policyTemplate.CRSVersion) {
			readyServerIDs = append(readyServerIDs, serverID)
			continue
		}
		if s.catalog == nil {
			packageErrors = append(packageErrors, fmt.Errorf("server %s needs CRS %s but package catalog is unavailable", serverID, policyTemplate.CRSVersion))
			continue
		}
		agentPackage, modulePackage, err := s.catalog.Resolve(server.Inventory)
		if err != nil {
			packageErrors = append(packageErrors, fmt.Errorf("server %s: %w", serverID, err))
			continue
		}
		if normalizeCRSVersion(modulePackage.CRSVersion) != normalizeCRSVersion(policyTemplate.CRSVersion) {
			packageErrors = append(packageErrors, fmt.Errorf("server %s package %s contains CRS %q, need %q", serverID, modulePackage.ID, modulePackage.CRSVersion, policyTemplate.CRSVersion))
			continue
		}
		if server.AgentPackageID == agentPackage.ID && server.ModulePackageID == modulePackage.ID {
			if server.PackageDeploymentStatus == "FAILED" {
				packageErrors = append(packageErrors, fmt.Errorf("server %s CRS package deployment failed: %s", serverID, server.PackageDeploymentDetail))
			}
			continue
		}
		if _, err := s.store.AssignPackages(ctx, binding.EnterpriseID, serverID, agentPackage.ID, modulePackage.ID, ""); err != nil {
			packageErrors = append(packageErrors, fmt.Errorf("queue CRS package for server %s: %w", serverID, err))
			continue
		}
		s.logger.Info("system_policy_crs_package_queued", "enterprise_id", binding.EnterpriseID, "server_id", serverID, "policy_revision", binding.ID, "module_package", modulePackage.ID, "crs_version", policyTemplate.CRSVersion)
	}
	return readyServerIDs, errors.Join(packageErrors...)
}

func (s *Server) createManagedPolicyRevision(ctx context.Context, enterpriseID string, serverIDs []string, name, description, mode string, settings PolicySettings, migratedFrom string) (string, error) {
	metadata := ManagedPolicyMetadata{
		SchemaVersion: settings.SchemaVersion, TemplateKey: settings.TemplateKey, TemplateVersion: settings.TemplateVersion,
		CRSTrack: settings.CRSTrack, CRSVersion: settings.CRSVersion, Target: settings.Target, AutoUpdate: settings.AutoUpdate,
		PolicyOrigin: settings.PolicyOrigin, MigrationStatus: settings.MigrationStatus, MigratedFrom: migratedFrom,
	}
	artifact, settingsJSON, err := buildManagedPolicyArtifact(mode, settings.ParanoiaLevel, settings.InboundScore, settings.RequestBody, strings.Join(settings.ExcludedPaths, "\n"), strings.Join(settings.ExcludedIPs, "\n"), settings.CustomRules, metadata)
	if err != nil {
		return "", err
	}
	revisionID := randomID()
	hash, signature := s.policySigner.Sign(artifact)
	relativePath := filepath.Join("policies", revisionID+".conf")
	fullPath := filepath.Join(s.cfg.ArtifactRoot, relativePath)
	if err := writeArtifact(fullPath, artifact); err != nil {
		return "", err
	}
	if err := s.store.AssignPolicyToServers(ctx, enterpriseID, serverIDs, revisionID, truncate(name, 255), truncate(description, 1024), mode, settingsJSON, filepath.ToSlash(relativePath), hash, signature, ""); err != nil {
		_ = os.Remove(fullPath)
		return "", err
	}
	return revisionID, nil
}

func normalizeCRSVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}
