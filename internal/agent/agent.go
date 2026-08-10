package agent

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/policybundle"
)

type Agent struct {
	cfg                     config.Agent
	client                  *Client
	audit                   *AuditReader
	policy                  *PolicyApplier
	spool                   *EventSpool
	logger                  *slog.Logger
	packageRestartRequested string
}

func New(cfg config.Agent, logger *slog.Logger) (*Agent, error) {
	if err := os.MkdirAll(cfg.StateDirectory, 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.SpoolDirectory, 0o750); err != nil {
		return nil, err
	}
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, client: client, audit: NewAuditReader(cfg.AuditLog, cfg.StateDirectory), policy: NewPolicyApplier(cfg), spool: NewEventSpool(cfg.SpoolDirectory, cfg.SpoolMaxBytes), logger: logger}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.runControlCycle(ctx); err != nil {
		a.logger.Warn("initial_cycle_failed", "error", err)
	}
	eventLoopDone := make(chan struct{})
	go func() {
		defer close(eventLoopDone)
		a.runEventLoop(ctx)
	}()
	heartbeatTimer := time.NewTimer(a.nextHeartbeatDelay())
	defer heartbeatTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			<-eventLoopDone
			return ctx.Err()
		case <-heartbeatTimer.C:
			if err := a.runControlCycle(ctx); err != nil {
				a.logger.Warn("agent_cycle_failed", "error", err)
			}
			heartbeatTimer.Reset(a.nextHeartbeatDelay())
		}
	}
}

func (a *Agent) runEventLoop(ctx context.Context) {
	eventDelay := a.cfg.EventFlushInterval
	eventTimer := time.NewTimer(eventDelay)
	defer eventTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-eventTimer.C:
			if a.client.ServerID() != "" {
				if err := a.flushAudit(ctx); err != nil {
					eventDelay = min(eventDelay*2, a.cfg.EventRetryMax)
					a.logger.Warn("event_flush_failed", "error", err, "retry_in", eventDelay)
				} else {
					eventDelay = a.cfg.EventFlushInterval
				}
			}
			eventTimer.Reset(eventDelay)
		}
	}
}

func (a *Agent) nextHeartbeatDelay() time.Duration {
	return a.cfg.Heartbeat + time.Duration(rand.IntN(5000))*time.Millisecond
}

func (a *Agent) runControlCycle(ctx context.Context) error {
	inventory, err := CollectInventory(ctx, a.cfg)
	if err != nil {
		return err
	}
	for _, candidate := range inventory.WebServerCandidates {
		if candidate.Kind == inventory.WebServer && candidate.BuildHash == inventory.WebServerBuild {
			a.policy.ConfigureWebServer(candidate.Binary, inventory.WebServerControl)
			break
		}
	}
	if a.client.ServerID() == "" {
		if err := a.client.Enroll(ctx, inventory); err != nil {
			return err
		}
		a.logger.Info("agent_enrolled", "server_id", a.client.ServerID())
	}
	needsRenewal, expiresAt, err := a.client.CertificateExpiresWithin(a.cfg.CertificateRenewBefore)
	if err != nil {
		return fmt.Errorf("inspect agent certificate: %w", err)
	}
	if needsRenewal {
		if renewedUntil, renewErr := a.client.RenewCertificate(ctx); renewErr != nil {
			a.logger.Warn("certificate_renewal_failed", "error", renewErr, "current_expiry", expiresAt)
		} else {
			a.logger.Info("certificate_renewed", "expires_at", renewedUntil)
		}
	}
	state := a.currentDesiredState()
	spoolEvents, spoolBytes, err := a.spool.Stats()
	if err != nil {
		return err
	}
	lastCommandID, err := readStateValue(filepath.Join(a.cfg.StateDirectory, "last-command-id"))
	if err != nil {
		return err
	}
	heartbeat := model.HeartbeatRequest{Inventory: inventory, PolicyRevision: state.RevisionID, PolicyHash: state.SHA256, Status: "ONLINE", SpoolBytes: spoolBytes, SpoolEvents: spoolEvents, LastCommandID: lastCommandID}
	if err := a.client.Heartbeat(ctx, heartbeat); err != nil {
		return err
	}
	if err := a.confirmPendingAgentUpdate(inventory.AgentVersion); err != nil {
		return err
	}
	if state.RevisionID != "" {
		if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "last-heartbeat-policy"), []byte(state.RevisionID+"\n"), 0o640); err != nil {
			return err
		}
	}
	desired, err := a.client.DesiredState(ctx)
	if err != nil {
		return err
	}
	persistedDesired := desired
	if desired.RevisionID != "" && (desired.RevisionID != state.RevisionID || desired.SHA256 != state.SHA256) {
		if !inventory.IntegrationReady || !inventory.ConfigTestOK {
			persistedDesired.RevisionID = state.RevisionID
			persistedDesired.ArtifactURL = state.ArtifactURL
			persistedDesired.ArtifactFormat = state.ArtifactFormat
			persistedDesired.SHA256 = state.SHA256
			persistedDesired.Signature = state.Signature
			persistedDesired.Mode = state.Mode
			persistedDesired.BasePolicy = state.BasePolicy
			persistedDesired.OverridePolicy = state.OverridePolicy
		} else {
			applyErr := func() error {
				if err := a.client.EnsurePolicyPublicKey(ctx); err != nil {
					return err
				}
				if desired.ArtifactFormat == policybundle.FormatOverride {
					if desired.BasePolicy == nil || desired.OverridePolicy == nil {
						return errors.New("split policy references are missing")
					}
					baseArtifact, err := a.client.DownloadBasePolicy(ctx, desired.BasePolicy.URL)
					if err != nil {
						return err
					}
					overrideArtifact, err := a.client.DownloadPolicy(ctx, desired.OverridePolicy.URL)
					if err != nil {
						return err
					}
					return a.policy.ApplySplit(ctx, inventory.WebServer, desired, baseArtifact, overrideArtifact)
				}
				artifact, err := a.client.DownloadPolicy(ctx, desired.ArtifactURL)
				if err != nil {
					return err
				}
				return a.policy.Apply(ctx, inventory.WebServer, desired, artifact)
			}()
			if applyErr != nil {
				_ = a.client.SendPolicyResult(ctx, desired.RevisionID, "FAILED", applyErr.Error())
				return applyErr
			}
			if err := a.client.SendPolicyResult(ctx, desired.RevisionID, "APPLIED", ""); err != nil {
				return err
			}
			a.logger.Info("policy_applied", "revision", desired.RevisionID, "mode", desired.Mode)
		}
	}
	if err := a.saveDesiredState(persistedDesired); err != nil {
		return err
	}
	if desired.PackageDeployment != nil {
		deployment := *desired.PackageDeployment
		installedID, err := readStateValue(filepath.Join(a.cfg.StateDirectory, "last-package-deployment"))
		if err != nil {
			return err
		}
		failedID, err := readStateValue(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment"))
		if err != nil {
			return err
		}
		reportedID, err := readStateValue(filepath.Join(a.cfg.StateDirectory, "reported-package-deployment"))
		if err != nil {
			return err
		}
		if failedID == deployment.ID {
			if reportedID != deployment.ID {
				detail, detailErr := readStateValue(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment-detail"))
				if detailErr != nil {
					return detailErr
				}
				if detail == "" {
					detail = "이전 패키지 적용 실패 상태를 유지합니다."
				}
				if err := a.client.SendPackageResult(ctx, deployment.ID, "FAILED", detail); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "reported-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
			}
			return nil
		}
		if installedID == deployment.ID {
			if reportedID != deployment.ID && a.packageRestartRequested != deployment.ID && packageDeploymentMatchesInventory(deployment, inventory) {
				if err := a.client.SendPackageResult(ctx, deployment.ID, "APPLIED", packageDeploymentAppliedDetail(deployment)); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "reported-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
				a.logger.Info("packages_applied", "deployment_id", deployment.ID, "scope", model.NormalizePackageScope(deployment.Scope), "agent_package", deployment.Agent.ID, "module_package", deployment.Module.ID)
			} else if reportedID != deployment.ID && failedID != deployment.ID && a.packageRestartRequested == "" {
				detail := packageDeploymentMismatchDetail(deployment, inventory)
				if err := a.client.SendPackageResult(ctx, deployment.ID, "FAILED", detail); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment-detail"), []byte(detail+"\n"), 0o640); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "reported-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
			}
		} else if failedID != deployment.ID {
			agentUpdated, applyErr := a.applyPackageDeployment(ctx, deployment)
			if applyErr != nil {
				if err := a.client.SendPackageResult(ctx, deployment.ID, "FAILED", applyErr.Error()); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "failed-package-deployment-detail"), []byte(applyErr.Error()+"\n"), 0o640); err != nil {
					return err
				}
				if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "reported-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
					return err
				}
				return applyErr
			}
			if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "last-package-deployment"), []byte(deployment.ID+"\n"), 0o640); err != nil {
				return err
			}
			if agentUpdated {
				a.packageRestartRequested = deployment.ID
				restartErr := error(nil)
				if model.NormalizePackageScope(deployment.Scope) == model.PackageScopeAgent {
					restartErr = a.startAgentUpdateSupervisor(deployment)
				} else {
					restartErr = restartUpdatedAgent()
				}
				if restartErr != nil {
					_ = a.client.SendPackageResult(ctx, deployment.ID, "FAILED", restartErr.Error())
					return restartErr
				}
			}
			return nil
		}
	}
	if err := a.executeNextCommand(ctx); err != nil {
		return err
	}
	return nil
}

func (a *Agent) confirmPendingAgentUpdate(agentVersion string) error {
	path := filepath.Join(a.cfg.StateDirectory, "pending-agent-update.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending pendingAgentUpdate
	if json.Unmarshal(raw, &pending) != nil || !safeStateID(pending.DeploymentID) || pending.TargetVersion == "" {
		return errors.New("pending Agent update state is invalid")
	}
	if pending.TargetVersion != agentVersion {
		return nil
	}
	return atomicWrite(filepath.Join(a.cfg.StateDirectory, "agent-update-confirmed-"+pending.DeploymentID), []byte(agentVersion+"\n"), 0o640)
}

func packageDeploymentMatchesInventory(deployment model.PackageDeployment, inventory model.Inventory) bool {
	if inventory.AgentVersion != deployment.Agent.Version {
		return false
	}
	return model.NormalizePackageScope(deployment.Scope) == model.PackageScopeAgent || inventory.ModuleVersion == deployment.Module.Version
}

func packageDeploymentAppliedDetail(deployment model.PackageDeployment) string {
	if model.NormalizePackageScope(deployment.Scope) == model.PackageScopeAgent {
		return "Agent가 재시작 후 새 버전으로 mTLS 연결을 확인했습니다. 웹서버 모듈과 정책은 변경하지 않았습니다."
	}
	return "모듈 설치 후 Agent가 설치 버전을 확인했습니다. 웹서버 연동은 별도 안내에 따라 활성화해야 합니다."
}

func packageDeploymentMismatchDetail(deployment model.PackageDeployment, inventory model.Inventory) string {
	if model.NormalizePackageScope(deployment.Scope) == model.PackageScopeAgent {
		return fmt.Sprintf("재시작 후 Agent 버전 불일치: actual=%s expected=%s", inventory.AgentVersion, deployment.Agent.Version)
	}
	return fmt.Sprintf("재시작 후 설치 버전 불일치: agent=%s/%s module=%s/%s", inventory.AgentVersion, deployment.Agent.Version, inventory.ModuleVersion, deployment.Module.Version)
}

func (a *Agent) flushAudit(ctx context.Context) error {
	pending, err := a.spool.Pending()
	if err != nil {
		return err
	}
	sentBatches := 0
	for _, item := range pending {
		if sentBatches >= a.cfg.EventBatchesPerFlush {
			return nil
		}
		if err := a.client.SendEvents(ctx, item.Batch); err != nil {
			return err
		}
		if err := a.audit.Commit(item.NextPosition); err != nil {
			return err
		}
		if err := a.spool.Remove(item); err != nil {
			return err
		}
		sentBatches++
	}
	for sentBatches < a.cfg.EventBatchesPerFlush {
		events, nextPosition, err := a.audit.ReadBatch(a.cfg.EventBatchSize)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			if !nextPosition.Empty() {
				return a.audit.Commit(nextPosition)
			}
			return nil
		}
		policyRevision := a.currentDesiredState().RevisionID
		for index := range events {
			if events[index].PolicyRevision == "" {
				events[index].PolicyRevision = policyRevision
			}
		}
		batch := model.EventBatch{BatchID: randomID(), Events: events}
		item, err := a.spool.Put(batch, nextPosition)
		if err != nil {
			return err
		}
		if err := a.client.SendEvents(ctx, batch); err != nil {
			return err
		}
		if err := a.audit.Commit(nextPosition); err != nil {
			return err
		}
		if err := a.spool.Remove(item); err != nil {
			return err
		}
		sentBatches++
	}
	return nil
}

func (a *Agent) saveDesiredState(state model.DesiredState) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(a.cfg.StateDirectory, "desired-state.json"), append(raw, '\n'), 0o640)
}

func (a *Agent) currentDesiredState() model.DesiredState {
	raw, err := os.ReadFile(filepath.Join(a.cfg.StateDirectory, "desired-state.json"))
	if err != nil {
		return model.DesiredState{Mode: "DetectionOnly"}
	}
	var state model.DesiredState
	if json.Unmarshal(raw, &state) != nil {
		return model.DesiredState{Mode: "DetectionOnly"}
	}
	return state
}

func randomID() string {
	raw := make([]byte, 16)
	if _, err := crand.Read(raw); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
