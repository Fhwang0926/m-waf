package manager

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

type policyServerChoice struct {
	Server   ServerRecord
	Selected bool
}

const (
	PolicyStrategyManual    = "MANUAL"
	PolicyStrategyAutomatic = "AUTOMATIC"
	PolicyStrategyPinned    = "PINNED"

	EnterprisePolicyActive       = "ACTIVE"
	EnterprisePolicyLegacyLocked = "LEGACY_LOCKED"
)

type SystemPolicyVersionRecord struct {
	ID                 string
	Key                string
	Version            string
	SchemaVersion      int
	Name               string
	Description        string
	CRSTrack           string
	CRSVersion         string
	Status             string
	TemplateSHA256     string
	SourceCommit       string
	HotRuleSetVersion  string
	HotRuleSetSHA256   string
	Defaults           systempolicy.Defaults
	MigrationNotes     []string
	EnterpriseCount    int
	ServerCount        int
	ActiveRolloutCount int
	CreatedAt          time.Time
}

func (p SystemPolicyVersionRecord) DefaultModeLabel() string {
	if p.Defaults.Mode == "DetectionOnly" {
		return "탐지만"
	}
	return "차단"
}

func (p SystemPolicyVersionRecord) StatusLabel() string {
	switch p.Status {
	case "PUBLISHED":
		return "게시됨"
	case "DEPRECATED":
		return "사용 중단 예정"
	case "WITHDRAWN":
		return "회수됨"
	default:
		return p.Status
	}
}

func (p SystemPolicyVersionRecord) CanWithdraw() bool {
	return (p.Status == systempolicy.StatusPublished || p.Status == systempolicy.StatusDeprecated) && p.EnterpriseCount == 0 && p.ActiveRolloutCount == 0
}

func (p SystemPolicyVersionRecord) WithdrawBlockReason() string {
	switch {
	case p.Status == systempolicy.StatusWithdrawn:
		return "이미 회수된 시스템 정책입니다."
	case p.EnterpriseCount != 0:
		return "사용 중인 기업 정책이 있어 회수할 수 없습니다."
	case p.ActiveRolloutCount != 0:
		return "진행 중인 단계 배포가 있어 회수할 수 없습니다."
	case p.Status != systempolicy.StatusPublished && p.Status != systempolicy.StatusDeprecated:
		return "현재 상태에서는 회수할 수 없습니다."
	default:
		return ""
	}
}

type EnterprisePolicyRecord struct {
	ID                         string
	EnterpriseID               string
	EnterpriseName             string
	Name                       string
	Description                string
	Target                     string
	SystemPolicyKey            string
	SystemPolicyName           string
	CurrentSystemPolicyID      string
	CurrentSystemPolicyVersion string
	CurrentCRSVersion          string
	LatestSystemPolicyID       string
	LatestSystemPolicyVersion  string
	LatestCRSVersion           string
	UpdateStrategy             string
	Status                     string
	CurrentRevisionID          string
	PreviousRevisionID         string
	CurrentMode                string
	CurrentSettings            PolicySettings
	CurrentConfiguration       *PolicyConfiguration
	LatestRolloutID            string
	LatestRolloutStatus        string
	HasActiveRollout           bool
	MigrationRequired          bool
	MigrationDetail            string
	ServerCount                int
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

func (p EnterprisePolicyRecord) HasUpdate() bool {
	return p.Status == EnterprisePolicyActive && p.CurrentSystemPolicyID != "" && p.LatestSystemPolicyID != "" && p.LatestSystemPolicyID != p.CurrentSystemPolicyID
}

func (p EnterprisePolicyRecord) StrategyLabel() string {
	switch p.UpdateStrategy {
	case PolicyStrategyManual:
		return "수동 승인"
	case PolicyStrategyAutomatic:
		return "자동 채택"
	case PolicyStrategyPinned:
		return "버전 고정"
	default:
		return p.UpdateStrategy
	}
}

func (p EnterprisePolicyRecord) TargetLabel() string {
	return fmt.Sprintf("연결 서버 %d대", p.ServerCount)
}

type PolicyRevisionRecord struct {
	ID                    string
	EnterprisePolicyID    string
	SystemPolicyVersionID string
	ParentRevisionID      string
	Name                  string
	Description           string
	Mode                  string
	Settings              PolicySettings
	ArtifactPath          string
	ArtifactSHA256        string
	ArtifactSignature     string
	PolicyOrigin          string
	CreatedAt             time.Time
}

type PolicyRolloutRecord struct {
	ID                          string
	EnterprisePolicyID          string
	EnterpriseID                string
	PolicyName                  string
	Target                      string
	Type                        string
	Status                      string
	FromRevisionID              string
	TargetSystemPolicyVersionID string
	TargetRevisionID            string
	ExpectedRevisionID          string
	Detail                      string
	PendingCount                int
	DeferredCount               int
	AppliedCount                int
	FailedCount                 int
	CreatedAt                   time.Time
	UpdatedAt                   time.Time
}

type PolicyRolloutTargetRecord struct {
	RolloutID              string
	ServerID               string
	ServerName             string
	BatchNo                int
	Status                 string
	ResumeStatus           string
	SourceAgentPackageID   string
	SourceModulePackageID  string
	SourceRevisionID       string
	TargetAgentPackageID   string
	TargetModulePackageID  string
	TransitionRevisionID   string
	FinalRevisionID        string
	PackageDeploymentID    string
	Detail                 string
	ServerStatus           string
	Online                 bool
	InventoryCRSVersion    string
	CurrentPolicyRevision  string
	DesiredPolicyRevision  string
	PackageStatus          string
	PolicyStatus           string
	TransitionPolicyStatus string
	StabilizedAt           sql.NullTime
	UpdatedAt              time.Time
}

type PolicyRevisionInput struct {
	ID                    string
	SystemPolicyVersionID string
	ParentRevisionID      string
	Name                  string
	Description           string
	Mode                  string
	SettingsJSON          string
	ArtifactPath          string
	ArtifactSHA256        string
	ArtifactSignature     string
	PolicyOrigin          string
	Configuration         *PolicyConfiguration
}
