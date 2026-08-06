package manager

import (
	"net/http"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func (s *Server) policyResult(w http.ResponseWriter, r *http.Request) {
	var result model.DeploymentResult
	if err := decodeJSON(w, r, &result, 16<<10); err != nil {
		return
	}
	if result.Status != "APPLIED" && result.Status != "FAILED" {
		writeProblem(w, http.StatusBadRequest, "status must be APPLIED or FAILED")
		return
	}
	result.Detail = truncate(strings.TrimSpace(result.Detail), 4096)
	if err := s.store.UpdatePolicyDeploymentResult(r.Context(), agentIDFrom(r), r.PathValue("id"), result.Status, result.Detail); err != nil {
		writeProblem(w, http.StatusNotFound, "policy deployment not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

func (s *Server) packageDeploymentResult(w http.ResponseWriter, r *http.Request) {
	var result model.DeploymentResult
	if err := decodeJSON(w, r, &result, 16<<10); err != nil {
		return
	}
	if result.Status != "APPLIED" && result.Status != "FAILED" {
		writeProblem(w, http.StatusBadRequest, "status must be APPLIED or FAILED")
		return
	}
	result.Detail = truncate(strings.TrimSpace(result.Detail), 4096)
	if err := s.store.UpdatePackageDeploymentResult(r.Context(), agentIDFrom(r), r.PathValue("id"), result.Status, result.Detail); err != nil {
		writeProblem(w, http.StatusNotFound, "package deployment not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

func (s *Server) nextAgentCommand(w http.ResponseWriter, r *http.Request) {
	command, err := s.store.NextCommand(r.Context(), agentIDFrom(r))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "load agent command")
		return
	}
	writeJSON(w, http.StatusOK, command)
}

func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request) {
	var result model.DeploymentResult
	if err := decodeJSON(w, r, &result, 16<<10); err != nil {
		return
	}
	if result.Status != "ACCEPTED" && result.Status != "FAILED" {
		writeProblem(w, http.StatusBadRequest, "status must be ACCEPTED or FAILED")
		return
	}
	result.Detail = truncate(strings.TrimSpace(result.Detail), 4096)
	if err := s.store.UpdateCommandResult(r.Context(), agentIDFrom(r), r.PathValue("id"), result.Status, result.Detail); err != nil {
		writeProblem(w, http.StatusNotFound, "agent command not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}
