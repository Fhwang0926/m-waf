// Package protocol defines the versioned wire contract used by an Agent when
// it initiates HTTPS requests to Manager. Manager never opens a connection to
// an Agent and Agent does not expose a management listener.
package protocol

import (
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const (
	VersionV1 = "v1"

	HealthLivePattern  = "GET /health/live"
	HealthReadyPattern = "GET /health/ready"

	BootstrapInstallerPattern = "GET /bootstrap/v1/install.sh"
	BootstrapSessionPattern   = "POST /bootstrap/v1/sessions"
	BootstrapResolvePattern   = "POST /bootstrap/v1/packages/resolve"
	BootstrapPackagePattern   = "GET /bootstrap/v1/packages/{id}"
	PackageKeyPattern         = "GET /packages/v1/keys"

	EnrollPattern           = "POST /agent/v1/enroll"
	HeartbeatPattern        = "POST /agent/v1/heartbeat"
	CertificateRenewPattern = "POST /agent/v1/certificate/renew"
	DesiredStatePattern     = "GET /agent/v1/desired-state"
	PolicyKeyPattern        = "GET /agent/v1/policy-key"
	PolicyArtifactPattern   = "GET /agent/v1/artifacts/{id}"
	AgentPackagePattern     = "GET /agent/v1/packages/{id}"
	EventBatchPattern       = "POST /agent/v1/events/batch"
	PolicyResultPattern     = "POST /agent/v1/policies/{id}/result"
	PackageResultPattern    = "POST /agent/v1/package-deployments/{id}/result"
	NextCommandPattern      = "GET /agent/v1/commands/next"
	CommandResultPattern    = "POST /agent/v1/commands/{id}/result"

	BootstrapInstallerPath = "/bootstrap/v1/install.sh"
	BootstrapSessionPath   = "/bootstrap/v1/sessions"
	BootstrapResolvePath   = "/bootstrap/v1/packages/resolve"
	PackageKeyPath         = "/packages/v1/keys"
	EnrollPath             = "/agent/v1/enroll"
	HeartbeatPath          = "/agent/v1/heartbeat"
	CertificateRenewPath   = "/agent/v1/certificate/renew"
	DesiredStatePath       = "/agent/v1/desired-state"
	PolicyKeyPath          = "/agent/v1/policy-key"
	EventBatchPath         = "/agent/v1/events/batch"
	NextCommandPath        = "/agent/v1/commands/next"

	BootstrapPackagePrefix = "/bootstrap/v1/packages/"
	PolicyArtifactPrefix   = "/agent/v1/artifacts/"
	AgentPackagePrefix     = "/agent/v1/packages/"
)

// AgentV1Contract is the machine-readable description of the stable Agent
// protocol. It keeps direction, authentication, limits and route families in
// one structure so client and server changes are reviewed against one spec.
type AgentV1Contract struct {
	Version             string             `json:"version"`
	Direction           string             `json:"direction"`
	Transport           string             `json:"transport"`
	DefaultPollSeconds  int                `json:"default_poll_seconds"`
	EnrollmentAuth      string             `json:"enrollment_auth"`
	AuthenticatedAuth   string             `json:"authenticated_auth"`
	PolicyArtifactLimit int64              `json:"policy_artifact_limit"`
	PackageLimit        int64              `json:"package_limit"`
	EventBatchLimit     int                `json:"event_batch_limit"`
	Endpoints           []EndpointContract `json:"endpoints"`
}

type EndpointContract struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Auth         string `json:"auth"`
	RequestType  string `json:"request_type,omitempty"`
	ResponseType string `json:"response_type,omitempty"`
}

var AgentV1 = AgentV1Contract{
	Version:             VersionV1,
	Direction:           "agent-to-manager",
	Transport:           "https",
	DefaultPollSeconds:  30,
	EnrollmentAuth:      "short-lived-token-and-csr",
	AuthenticatedAuth:   "mutual-tls",
	PolicyArtifactLimit: 64 << 20,
	PackageLimit:        1 << 30,
	EventBatchLimit:     500,
	Endpoints: []EndpointContract{
		{Method: "POST", Path: EnrollPath, Auth: "enrollment-token", RequestType: "EnrollRequest", ResponseType: "EnrollResponse"},
		{Method: "POST", Path: HeartbeatPath, Auth: "mTLS", RequestType: "HeartbeatRequest"},
		{Method: "POST", Path: CertificateRenewPath, Auth: "mTLS", RequestType: "CertificateRenewRequest", ResponseType: "CertificateRenewResponse"},
		{Method: "GET", Path: DesiredStatePath, Auth: "mTLS", ResponseType: "DesiredState"},
		{Method: "GET", Path: PolicyKeyPath, Auth: "mTLS", ResponseType: "PEM"},
		{Method: "GET", Path: "/agent/v1/artifacts/{id}", Auth: "mTLS", ResponseType: "policy artifact"},
		{Method: "GET", Path: "/agent/v1/packages/{id}", Auth: "mTLS", ResponseType: "package artifact"},
		{Method: "POST", Path: EventBatchPath, Auth: "mTLS", RequestType: "EventBatch"},
		{Method: "POST", Path: "/agent/v1/policies/{id}/result", Auth: "mTLS", RequestType: "DeploymentResult"},
		{Method: "POST", Path: "/agent/v1/package-deployments/{id}/result", Auth: "mTLS", RequestType: "DeploymentResult"},
		{Method: "GET", Path: NextCommandPath, Auth: "mTLS", ResponseType: "AgentCommand"},
		{Method: "POST", Path: "/agent/v1/commands/{id}/result", Auth: "mTLS", RequestType: "DeploymentResult"},
	},
}

// Wire payload aliases keep the public protocol names explicit without
// breaking the existing model package used by persisted domain records.
type EnrollRequest = model.EnrollRequest
type EnrollResponse = model.EnrollResponse
type CertificateRenewRequest = model.CertificateRenewRequest
type CertificateRenewResponse = model.CertificateRenewResponse
type HeartbeatRequest = model.HeartbeatRequest
type DesiredState = model.DesiredState
type PackageResolution = model.PackageResolution
type PackageDownload = model.PackageDownload
type PackageDeployment = model.PackageDeployment
type DeploymentResult = model.DeploymentResult
type AgentCommand = model.AgentCommand
type SecurityEvent = model.SecurityEvent
type EventBatch = model.EventBatch

func BootstrapPackagePath(id string) string {
	return BootstrapPackagePrefix + strings.TrimSpace(id)
}

func PolicyArtifactPath(id string) string {
	return PolicyArtifactPrefix + strings.TrimSpace(id)
}

func AgentPackagePath(id string) string {
	return AgentPackagePrefix + strings.TrimSpace(id)
}

func PolicyResultPath(id string) string {
	return "/agent/v1/policies/" + strings.TrimSpace(id) + "/result"
}

func PackageResultPath(id string) string {
	return "/agent/v1/package-deployments/" + strings.TrimSpace(id) + "/result"
}

func CommandResultPath(id string) string {
	return "/agent/v1/commands/" + strings.TrimSpace(id) + "/result"
}
