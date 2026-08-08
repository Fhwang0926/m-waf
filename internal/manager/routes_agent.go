package manager

import (
	"net/http"

	"github.com/Fhwang0926/m-waf/internal/protocol"
)

func (s *Server) registerAgentRoutes(mux *http.ServeMux) {
	mux.Handle(protocol.BootstrapInstallerPattern, s.limitBootstrap(http.HandlerFunc(s.bootstrapInstaller)))
	mux.Handle(protocol.BootstrapSessionPattern, s.limitBootstrap(http.HandlerFunc(s.createBootstrapSession)))
	mux.Handle(protocol.BootstrapResolvePattern, s.limitBootstrap(http.HandlerFunc(s.resolvePackages)))
	mux.HandleFunc(protocol.BootstrapPackagePattern, s.bootstrapPackage)
	mux.Handle(protocol.PackageKeyPattern, s.limitBootstrap(http.HandlerFunc(s.packagePublicKey)))
	mux.Handle(protocol.EnrollPattern, s.limitBootstrap(http.HandlerFunc(s.enroll)))
	mux.Handle(protocol.HeartbeatPattern, s.requireAgent(http.HandlerFunc(s.heartbeat)))
	mux.Handle(protocol.CertificateRenewPattern, s.requireAgent(http.HandlerFunc(s.renewCertificate)))
	mux.Handle(protocol.DesiredStatePattern, s.requireAgent(http.HandlerFunc(s.desiredState)))
	mux.Handle(protocol.PolicyKeyPattern, s.requireAgent(http.HandlerFunc(s.policyPublicKey)))
	mux.Handle(protocol.PolicyArtifactPattern, s.requireAgent(http.HandlerFunc(s.policyArtifact)))
	mux.Handle(protocol.AgentPackagePattern, s.requireAgent(http.HandlerFunc(s.agentPackage)))
	mux.Handle(protocol.EventBatchPattern, s.requireAgent(http.HandlerFunc(s.eventBatch)))
	mux.Handle(protocol.PolicyResultPattern, s.requireAgent(http.HandlerFunc(s.policyResult)))
	mux.Handle(protocol.PackageResultPattern, s.requireAgent(http.HandlerFunc(s.packageDeploymentResult)))
	mux.Handle(protocol.NextCommandPattern, s.requireAgent(http.HandlerFunc(s.nextAgentCommand)))
	mux.Handle(protocol.CommandResultPattern, s.requireAgent(http.HandlerFunc(s.agentCommandResult)))
}
