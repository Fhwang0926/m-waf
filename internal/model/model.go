package model

import "time"

const (
	IntegrationModeDistro   = "distro"
	IntegrationModeExternal = "external"
)

func NormalizeIntegrationMode(mode string) string {
	if mode == "" {
		return IntegrationModeDistro
	}
	return mode
}

type Inventory struct {
	Hostname         string   `json:"hostname"`
	OSID             string   `json:"os_id"`
	OSVersion        string   `json:"os_version"`
	Architecture     string   `json:"architecture"`
	WebServer        string   `json:"web_server"`
	WebServerVersion string   `json:"web_server_version"`
	WebServerBuild   string   `json:"web_server_build_hash"`
	IntegrationMode  string   `json:"integration_mode,omitempty"`
	InstallationMode string   `json:"installation_mode,omitempty"`
	AgentVersion     string   `json:"agent_version,omitempty"`
	ModuleVersion    string   `json:"module_version,omitempty"`
	CRSVersion       string   `json:"crs_version,omitempty"`
	ConnectorVersion string   `json:"connector_version,omitempty"`
	ConnectorLoaded  bool     `json:"connector_loaded,omitempty"`
	ConfigTestOK     bool     `json:"config_test_ok,omitempty"`
	PolicyFormats    []string `json:"policy_formats,omitempty"`
}

type PackageArtifact struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	OSID             string   `json:"os_id"`
	OSVersion        string   `json:"os_version"`
	Architecture     string   `json:"architecture"`
	WebServer        string   `json:"web_server,omitempty"`
	WebServerVersion string   `json:"web_server_version,omitempty"`
	WebServerBuild   string   `json:"web_server_build_hash,omitempty"`
	CRSVersion       string   `json:"crs_version,omitempty"`
	IntegrationMode  string   `json:"integration_mode,omitempty"`
	Path             string   `json:"path"`
	Size             int64    `json:"size"`
	SHA256           string   `json:"sha256"`
	RollbackID       string   `json:"rollback_id,omitempty"`
	PolicyFormats    []string `json:"policy_formats,omitempty"`
}

type BundleManifest struct {
	SchemaVersion int                    `json:"schema_version"`
	BundleVersion string                 `json:"bundle_version"`
	SourceCommit  string                 `json:"source_commit"`
	CreatedAt     time.Time              `json:"created_at"`
	ManagerAPIMin string                 `json:"manager_api_min"`
	ManagerAPIMax string                 `json:"manager_api_max"`
	Artifacts     []PackageArtifact      `json:"artifacts"`
	PolicySources []PolicySourceArtifact `json:"policy_sources,omitempty"`
}

type PolicySourceArtifact struct {
	ID                   string   `json:"id"`
	Provider             string   `json:"provider"`
	Repository           string   `json:"repository"`
	Channel              string   `json:"channel"`
	Version              string   `json:"version"`
	Tag                  string   `json:"tag"`
	Commit               string   `json:"commit"`
	TagObjectSHA         string   `json:"tag_object_sha,omitempty"`
	TagSignatureVerified bool     `json:"tag_signature_verified,omitempty"`
	ArchivePath          string   `json:"archive_path,omitempty"`
	ArchiveSize          int64    `json:"archive_size,omitempty"`
	ArchiveSHA256        string   `json:"archive_sha256"`
	IndexPath            string   `json:"index_path"`
	IndexSize            int64    `json:"index_size"`
	IndexSHA256          string   `json:"index_sha256"`
	ArtifactFormat       string   `json:"artifact_format,omitempty"`
	CompatiblePackageIDs []string `json:"compatible_package_ids,omitempty"`
}

type PackageResolution struct {
	BundleVersion string          `json:"bundle_version"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Agent         PackageDownload `json:"agent"`
	Module        PackageDownload `json:"module"`
}

type PackageDownload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	URL        string `json:"url"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	RollbackID string `json:"rollback_id,omitempty"`
}

type EnrollRequest struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	CSRPEM    string    `json:"csr_pem"`
	Inventory Inventory `json:"inventory"`
}

type EnrollResponse struct {
	ServerID        string `json:"server_id"`
	CertificatePEM  string `json:"certificate_pem"`
	CACertificate   string `json:"ca_certificate_pem"`
	PolicyPublicKey string `json:"policy_public_key_pem"`
	AgentAPI        string `json:"agent_api"`
}

type CertificateRenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type CertificateRenewResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type HeartbeatRequest struct {
	Inventory      Inventory `json:"inventory"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
	PolicyHash     string    `json:"policy_hash,omitempty"`
	Status         string    `json:"status"`
	SpoolBytes     int64     `json:"spool_bytes,omitempty"`
	SpoolEvents    int       `json:"spool_events,omitempty"`
	LastCommandID  string    `json:"last_command_id,omitempty"`
}

type DesiredState struct {
	RevisionID        string             `json:"revision_id"`
	ArtifactURL       string             `json:"artifact_url,omitempty"`
	ArtifactFormat    string             `json:"artifact_format,omitempty"`
	SHA256            string             `json:"sha256,omitempty"`
	Signature         string             `json:"signature,omitempty"`
	Mode              string             `json:"mode"`
	AgentPackageID    string             `json:"agent_package_id,omitempty"`
	ModulePackageID   string             `json:"module_package_id,omitempty"`
	PackageDeployment *PackageDeployment `json:"package_deployment,omitempty"`
}

type PackageDeployment struct {
	ID     string          `json:"id"`
	Agent  PackageDownload `json:"agent"`
	Module PackageDownload `json:"module"`
}

type DeploymentResult struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type AgentCommand struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

type SecurityEvent struct {
	EventID        string    `json:"event_id"`
	OccurredAt     time.Time `json:"occurred_at"`
	TransactionID  string    `json:"transaction_id,omitempty"`
	Service        string    `json:"service,omitempty"`
	Method         string    `json:"method,omitempty"`
	URI            string    `json:"uri,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	RuleID         string    `json:"rule_id,omitempty"`
	Message        string    `json:"message,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Blocked        bool      `json:"blocked"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
}

type EventBatch struct {
	BatchID string          `json:"batch_id"`
	Events  []SecurityEvent `json:"events"`
}
