package model

import "time"

type Inventory struct {
	Hostname         string `json:"hostname"`
	OSID             string `json:"os_id"`
	OSVersion        string `json:"os_version"`
	Architecture     string `json:"architecture"`
	WebServer        string `json:"web_server"`
	WebServerVersion string `json:"web_server_version"`
	WebServerBuild   string `json:"web_server_build_hash"`
	AgentVersion     string `json:"agent_version,omitempty"`
	ModuleVersion    string `json:"module_version,omitempty"`
	CRSVersion       string `json:"crs_version,omitempty"`
}

type PackageArtifact struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	OSID             string `json:"os_id"`
	OSVersion        string `json:"os_version"`
	Architecture     string `json:"architecture"`
	WebServer        string `json:"web_server,omitempty"`
	WebServerVersion string `json:"web_server_version,omitempty"`
	WebServerBuild   string `json:"web_server_build_hash,omitempty"`
	Path             string `json:"path"`
	Size             int64  `json:"size"`
	SHA256           string `json:"sha256"`
	RollbackID       string `json:"rollback_id,omitempty"`
}

type BundleManifest struct {
	SchemaVersion int               `json:"schema_version"`
	BundleVersion string            `json:"bundle_version"`
	SourceCommit  string            `json:"source_commit"`
	CreatedAt     time.Time         `json:"created_at"`
	ManagerAPIMin string            `json:"manager_api_min"`
	ManagerAPIMax string            `json:"manager_api_max"`
	Artifacts     []PackageArtifact `json:"artifacts"`
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

type HeartbeatRequest struct {
	Inventory      Inventory `json:"inventory"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
	PolicyHash     string    `json:"policy_hash,omitempty"`
	Status         string    `json:"status"`
	SpoolBytes     int64     `json:"spool_bytes,omitempty"`
	SpoolEvents    int       `json:"spool_events,omitempty"`
}

type DesiredState struct {
	RevisionID    string `json:"revision_id"`
	ArtifactURL   string `json:"artifact_url,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Signature     string `json:"signature,omitempty"`
	Mode          string `json:"mode"`
	AgentPackage  string `json:"agent_package_id,omitempty"`
	ModulePackage string `json:"module_package_id,omitempty"`
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
