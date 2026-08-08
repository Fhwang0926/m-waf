package manager

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crssource"
	"github.com/Fhwang0926/m-waf/internal/model"
)

func (s *Server) SyncLatestCRS(ctx context.Context) (model.PolicySourceArtifact, bool, error) {
	return s.SyncLatestCRSChannel(ctx, "stable")
}

func (s *Server) SyncLatestCRSChannel(ctx context.Context, channel string) (model.PolicySourceArtifact, bool, error) {
	s.sourceSyncMu.Lock()
	defer s.sourceSyncMu.Unlock()
	client := crssource.NewClient(s.cfg.CRSGitHubToken)
	fetched, err := client.FetchLatestChannel(ctx, channel, s.cfg.CRSLTSLine)
	if err != nil {
		var rejected *crssource.RejectedSourceError
		if errors.As(err, &rejected) {
			_ = s.store.recordRejectedCRSRelease(ctx, rejected.Source)
			_ = s.store.Audit(ctx, randomID(), "system:crs-sync", "crs_source.reject", rejected.Source.ID+":"+truncate(err.Error(), 512), "failed", "internal")
		}
		_ = s.store.Audit(ctx, randomID(), "system:crs-sync", "crs_source.sync", "official-"+channel+":"+truncate(err.Error(), 512), "failed", "internal")
		return model.PolicySourceArtifact{}, false, err
	}
	created, err := s.importRuntimePolicySource(fetched)
	if err == nil && created {
		_ = s.store.Audit(ctx, randomID(), "system:crs-sync", "crs_source.import", fetched.Source.ID+":"+fetched.Source.Commit, "success", "internal")
	} else if err != nil {
		_ = s.store.Audit(ctx, randomID(), "system:crs-sync", "crs_source.import", fetched.Source.ID+":"+truncate(err.Error(), 512), "failed", "internal")
	}
	return fetched.Source, created, err
}

func (s *Server) SyncCRSChannels(ctx context.Context) error {
	var syncErrors []error
	for _, channel := range []string{"lts", "stable"} {
		if _, _, err := s.SyncLatestCRSChannel(ctx, channel); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("%s: %w", channel, err))
		}
	}
	if err := errors.Join(syncErrors...); err != nil {
		return err
	}
	s.sourceMu.Lock()
	s.lastCRSSync = time.Now()
	s.sourceMu.Unlock()
	return nil
}

func (s *Server) syncOpenSourcePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		s.renderAdminError(w, r, http.StatusForbidden, "보안 정보가 만료되었습니다", "화면을 새로고침한 뒤 다시 시도하세요.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	channel := strings.ToLower(strings.TrimSpace(r.FormValue("channel")))
	if channel == "" {
		channel = "all"
	}
	if channel != "all" && channel != "stable" && channel != "lts" {
		s.renderAdminError(w, r, http.StatusBadRequest, "CRS 채널이 올바르지 않습니다", "전체, LTS 또는 Stable 채널을 선택하세요.")
		return
	}
	if channel == "all" {
		if err := s.SyncCRSChannels(ctx); err != nil {
			s.audit(r, sessionFrom(r).Username, "crs_source.sync", "official-lts-stable-v4", "failed")
			s.renderAdminError(w, r, http.StatusBadGateway, "공식 CRS 소스를 연동할 수 없습니다", err.Error())
			return
		}
		s.audit(r, sessionFrom(r).Username, "crs_source.sync", "official-lts-stable-v4", "success")
		http.Redirect(w, r, "/open-source-policies?synced=1", http.StatusSeeOther)
		return
	}
	source, created, err := s.SyncLatestCRSChannel(ctx, channel)
	if err != nil {
		s.audit(r, sessionFrom(r).Username, "crs_source.sync", "official-"+channel+"-v4", "failed")
		s.renderAdminError(w, r, http.StatusBadGateway, "공식 CRS 소스를 연동할 수 없습니다", err.Error())
		return
	}
	result := "current"
	if created {
		result = "synced"
	}
	s.audit(r, sessionFrom(r).Username, "crs_source.sync", source.ID+":"+source.Commit, "success")
	http.Redirect(w, r, "/open-source-policies?"+result+"=1&channel="+url.QueryEscape(channel), http.StatusSeeOther)
}

func (s *Server) apiSyncOpenSourcePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		writeProblem(w, http.StatusForbidden, "invalid csrf token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	channel := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("channel")))
	if channel == "" {
		channel = "stable"
	}
	if channel != "stable" && channel != "lts" {
		writeProblem(w, http.StatusBadRequest, "channel must be lts or stable")
		return
	}
	source, created, err := s.SyncLatestCRSChannel(ctx, channel)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, sessionFrom(r).Username, "crs_source.sync", source.ID+":"+source.Commit, "success")
	writeJSON(w, http.StatusOK, map[string]any{"source": source, "imported": created})
}
