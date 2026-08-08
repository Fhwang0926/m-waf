package manager

import (
	"database/sql"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const (
	PolicyStrategyManual    = "MANUAL"
	PolicyStrategyAutomatic = "AUTOMATIC"
	PolicyStrategyPinned    = "PINNED"

	EnterprisePolicyActive       = "ACTIVE"
	EnterprisePolicyLegacyLocked = "LEGACY_LOCKED"
)

type SystemPolicyVersionRecord struct {
	ID              string
	Key             string
	Version         string
	SchemaVersion   int
	Name            string
	Description     string
	CRSTrack        string
	CRSVersion      string
	Status          string
	TemplateSHA256  string
	SourceCommit    string
	Defaults        systempolicy.Defaults
	MigrationNotes  []string
	EnterpriseCount int
	ServerCount     int
	CreatedAt       time.Time
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
	return p.Status == systempolicy.StatusDeprecated && p.EnterpriseCount == 0
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
	kind, _, ok := strings.Cut(p.Target, ":")
	if !ok {
		return "기존 대상"
	}
	switch kind {
	case "server":
		return "개별 서버"
	case "group":
		return "서버 그룹"
	default:
		return "기존 대상"
	}
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
