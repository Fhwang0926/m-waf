package manager

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type DashboardSummary struct {
	ActiveServers  int
	OnlineServers  int
	Events24Hours  int
	Blocked24Hours int
}

func (s *Store) DashboardSummary(ctx context.Context, enterpriseID string, now time.Time) (DashboardSummary, error) {
	var summary DashboardSummary
	serverQuery := `SELECT COUNT(*),COALESCE(SUM(status='ONLINE' AND last_heartbeat_at>=?),0)
FROM servers WHERE revoked_at IS NULL`
	serverArgs := []any{now.Add(-serverOfflineAfter)}
	if enterpriseID != "" {
		serverQuery += ` AND enterprise_id=?`
		serverArgs = append(serverArgs, enterpriseID)
	}
	if err := s.db.QueryRowContext(ctx, serverQuery, serverArgs...).Scan(&summary.ActiveServers, &summary.OnlineServers); err != nil {
		return DashboardSummary{}, err
	}

	eventQuery := `SELECT COUNT(*),COALESCE(SUM(se.blocked),0)
FROM security_events se JOIN servers s ON s.id=se.agent_id
WHERE se.occurred_at>=?`
	eventArgs := []any{now.Add(-24 * time.Hour)}
	if enterpriseID != "" {
		eventQuery += ` AND s.enterprise_id=?`
		eventArgs = append(eventArgs, enterpriseID)
	}
	if err := s.db.QueryRowContext(ctx, eventQuery, eventArgs...).Scan(&summary.Events24Hours, &summary.Blocked24Hours); err != nil {
		return DashboardSummary{}, err
	}
	return summary, nil
}

func statusLabel(status string) string {
	switch status {
	case "ONLINE":
		return "온라인"
	case "OFFLINE":
		return "오프라인"
	case "APPLIED":
		return "적용 완료"
	case "FAILED":
		return "실패"
	case "PAUSED":
		return "일시 중지"
	case "QUEUED":
		return "배포 대기"
	case "CANARY":
		return "카나리 적용"
	case "EXPANDING":
		return "확대 배포"
	case "AWAITING_APPROVAL":
		return "승인 대기"
	case "PENDING":
		return "대기"
	case "TRANSITION_PENDING":
		return "전환 정책 대기"
	case "PACKAGE_PENDING":
		return "패키지 적용 대기"
	case "POLICY_PENDING":
		return "정책 적용 대기"
	case "ROLLBACK_PENDING":
		return "롤백 대기"
	case "DEFERRED":
		return "연결 대기"
	case "COMPLETED":
		return "완료"
	case "ACCEPTED":
		return "접수됨"
	case "ROLLED_BACK":
		return "롤백 완료"
	case "CANCELLED":
		return "취소됨"
	case "SUPERSEDED":
		return "대체됨"
	case "REVOKED":
		return "등록 해제"
	case "ACTIVE":
		return "운영 중"
	case "TERMINATED":
		return "운영 종료"
	case "":
		return "이력 없음"
	default:
		return status
	}
}

func modeLabel(mode string) string {
	switch mode {
	case "DetectionOnly":
		return "탐지만"
	case "On":
		return "탐지 및 차단"
	default:
		return mode
	}
}

func statusClass(status string) string {
	switch status {
	case "ONLINE", "APPLIED", "COMPLETED", "ROLLED_BACK", "ACTIVE":
		return "ok"
	case "FAILED", "PAUSED", "REVOKED", "TERMINATED":
		return "danger"
	case "":
		return ""
	default:
		return "warn"
	}
}

func (s ServerRecord) StatusLabel() string { return statusLabel(s.Status) }
func (s ServerRecord) StatusClass() string { return statusClass(s.Status) }
func (s ServerRecord) LastHeartbeatAge() string {
	if !s.LastHeartbeatAt.Valid {
		return "수신 대기"
	}
	elapsed := time.Since(s.LastHeartbeatAt.Time)
	if elapsed < 0 {
		elapsed = 0
	}
	switch {
	case elapsed < time.Minute:
		return "방금"
	case elapsed < time.Hour:
		return fmt.Sprintf("%d분 전", int(elapsed/time.Minute))
	case elapsed < 24*time.Hour:
		return fmt.Sprintf("%d시간 전", int(elapsed/time.Hour))
	default:
		return fmt.Sprintf("%d일 전", int(elapsed/(24*time.Hour)))
	}
}
func (s ServerRecord) PolicyDeploymentLabel() string  { return statusLabel(s.PolicyDeploymentStatus) }
func (s ServerRecord) PolicyDeploymentClass() string  { return statusClass(s.PolicyDeploymentStatus) }
func (s ServerRecord) PackageDeploymentLabel() string { return statusLabel(s.PackageDeploymentStatus) }
func (s ServerRecord) PackageDeploymentClass() string { return statusClass(s.PackageDeploymentStatus) }
func (s ServerRecord) InstallationStage() string {
	if s.PackageDeploymentStatus == "PENDING" {
		return "INSTALLING"
	}
	if s.Inventory.InstallationStage == "" {
		return "PLAN_REQUIRED"
	}
	return s.Inventory.InstallationStage
}
func (s ServerRecord) InstallationStageLabel() string {
	switch s.InstallationStage() {
	case "PROTECTED":
		return "보호 중"
	case "INTEGRATION_REQUIRED":
		return "웹서버 연동 필요"
	case "INSTALLING":
		return "설치 중"
	default:
		return "설치 유형 선택 필요"
	}
}
func (s ServerRecord) InstallationStageClass() string {
	if s.InstallationStage() == "PROTECTED" {
		return "ok"
	}
	return "warn"
}
func (s ServerRecord) LastCommandStatusLabel() string     { return statusLabel(s.LastCommandStatus) }
func (s ServerRecord) LastCommandStatusClass() string     { return statusClass(s.LastCommandStatus) }
func (p EnterprisePolicyRecord) CurrentModeLabel() string { return modeLabel(p.CurrentMode) }
func (p EnterprisePolicyRecord) RolloutStatusLabel() string {
	return statusLabel(p.LatestRolloutStatus)
}
func (p EnterprisePolicyRecord) RolloutStatusClass() string {
	return statusClass(p.LatestRolloutStatus)
}
func (p PolicyRevisionRecord) ModeLabel() string        { return modeLabel(p.Mode) }
func (p PolicyRolloutRecord) StatusLabel() string       { return statusLabel(p.Status) }
func (p PolicyRolloutRecord) StatusClass() string       { return statusClass(p.Status) }
func (p PolicyRolloutTargetRecord) StatusLabel() string { return statusLabel(p.Status) }
func (p PolicyRolloutTargetRecord) StatusClass() string { return statusClass(p.Status) }

func (p PolicyRolloutRecord) TypeLabel() string {
	switch p.Type {
	case "SEED":
		if p.FromRevisionID != "" {
			return "서버 연결·이동"
		}
		return "초기 적용"
	case "UPDATE":
		return "버전 업데이트"
	case "ROLLBACK":
		return "롤백"
	case "RECOVERY":
		return "자동 복구"
	default:
		return p.Type
	}
}

func (p PolicyRevisionRecord) OriginLabel() string {
	switch p.PolicyOrigin {
	case "administrator":
		return "관리자 생성"
	case "system-seed":
		return "시스템 초기 정책"
	case "legacy-conversion":
		return "기존 정책 전환"
	case "system-transition":
		return "CRS 전환 보호"
	default:
		return p.PolicyOrigin
	}
}

func (s *Server) renderAdminError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	w.WriteHeader(status)
	_ = s.templates.ExecuteTemplate(w, "error.html", s.viewData(r, "", map[string]any{
		"Status": status, "Title": title, "Message": message,
	}))
}
