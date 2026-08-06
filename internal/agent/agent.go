package agent

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
)

type Agent struct {
	cfg    config.Agent
	client *Client
	audit  *AuditReader
	policy *PolicyApplier
	spool  *EventSpool
	logger *slog.Logger
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
	return &Agent{cfg: cfg, client: client, audit: NewAuditReader(cfg.AuditLog, cfg.StateDirectory), policy: NewPolicyApplier(cfg), spool: NewEventSpool(cfg.SpoolDirectory), logger: logger}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.runCycle(ctx); err != nil {
		a.logger.Warn("initial_cycle_failed", "error", err)
	}
	for {
		jitter := time.Duration(rand.IntN(5000)) * time.Millisecond
		timer := time.NewTimer(a.cfg.Heartbeat + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			if err := a.runCycle(ctx); err != nil {
				a.logger.Warn("agent_cycle_failed", "error", err)
			}
		}
	}
}

func (a *Agent) runCycle(ctx context.Context) error {
	inventory, err := CollectInventory(ctx, a.cfg)
	if err != nil {
		return err
	}
	if a.client.ServerID() == "" {
		if err := a.client.Enroll(ctx, inventory); err != nil {
			return err
		}
		a.logger.Info("agent_enrolled", "server_id", a.client.ServerID())
	}
	state := a.currentDesiredState()
	spoolEvents, spoolBytes, err := a.spool.Stats()
	if err != nil {
		return err
	}
	heartbeat := model.HeartbeatRequest{Inventory: inventory, PolicyRevision: state.RevisionID, PolicyHash: state.SHA256, Status: "ONLINE", SpoolBytes: spoolBytes, SpoolEvents: spoolEvents}
	if err := a.client.Heartbeat(ctx, heartbeat); err != nil {
		return err
	}
	desired, err := a.client.DesiredState(ctx)
	if err != nil {
		return err
	}
	if desired.RevisionID != "" && (desired.RevisionID != state.RevisionID || desired.SHA256 != state.SHA256) {
		if err := a.client.EnsurePolicyPublicKey(ctx); err != nil {
			return err
		}
		artifact, err := a.client.DownloadPolicy(ctx, desired.ArtifactURL)
		if err != nil {
			return err
		}
		if err := a.policy.Apply(ctx, inventory.WebServer, desired, artifact); err != nil {
			return err
		}
		a.logger.Info("policy_applied", "revision", desired.RevisionID, "mode", desired.Mode)
	}
	if err := a.saveDesiredState(desired); err != nil {
		return err
	}
	if err := a.flushAudit(ctx); err != nil {
		return err
	}
	return nil
}

func (a *Agent) flushAudit(ctx context.Context) error {
	pending, err := a.spool.Pending()
	if err != nil {
		return err
	}
	for _, item := range pending {
		if err := a.client.SendEvents(ctx, item.Batch); err != nil {
			return err
		}
		if err := a.audit.Commit(item.NextOffset); err != nil {
			return err
		}
		if err := a.spool.Remove(item); err != nil {
			return err
		}
	}
	events, nextOffset, err := a.audit.ReadBatch(500)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		if nextOffset != 0 {
			return a.audit.Commit(nextOffset)
		}
		return nil
	}
	batch := model.EventBatch{BatchID: randomID(), Events: events}
	item, err := a.spool.Put(batch, nextOffset)
	if err != nil {
		return err
	}
	if err := a.client.SendEvents(ctx, batch); err != nil {
		return err
	}
	if err := a.audit.Commit(nextOffset); err != nil {
		return err
	}
	return a.spool.Remove(item)
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
