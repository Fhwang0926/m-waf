package manager

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type OverviewFilter struct {
	Range        string
	EnterpriseID string
	GroupID      string
	ServerID     string
	Since        time.Time
}

type OverviewSummary struct {
	ActiveServers   int     `json:"active_servers"`
	OnlineServers   int     `json:"online_servers"`
	EventCount      int     `json:"event_count"`
	BlockedCount    int     `json:"blocked_count"`
	BlockRate       float64 `json:"block_rate"`
	FailedRollouts  int     `json:"failed_rollouts"`
	PendingApproval int     `json:"pending_approval"`
}

type OverviewPoint struct {
	At      time.Time `json:"at"`
	Events  int       `json:"events"`
	Blocked int       `json:"blocked"`
}

type OverviewRank struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
	URL     string `json:"url"`
}

type OverviewAction struct {
	Kind       string `json:"kind"`
	Level      string `json:"level"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	TargetName string `json:"target_name"`
	URL        string `json:"url"`
}

type OverviewData struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Range       string           `json:"range"`
	RangeLabel  string           `json:"range_label"`
	RangeStart  time.Time        `json:"range_start"`
	RangeEnd    time.Time        `json:"range_end"`
	Summary     OverviewSummary  `json:"summary"`
	Series      []OverviewPoint  `json:"series"`
	TopRules    []OverviewRank   `json:"top_rules"`
	TopURIs     []OverviewRank   `json:"top_uris"`
	TopServers  []OverviewRank   `json:"top_servers"`
	Actions     []OverviewAction `json:"actions"`
	Recent      []EventRecord    `json:"recent_events"`
}

func (s *Store) CountBlockedEvents(ctx context.Context, serverID string, from, to time.Time, policyRevision string) (int, error) {
	query := `SELECT COUNT(*) FROM security_events WHERE agent_id=? AND blocked=1 AND occurred_at>=? AND occurred_at<?`
	args := []any{serverID, from.UTC(), to.UTC()}
	if policyRevision != "" {
		query += ` AND policy_revision=?`
		args = append(args, policyRevision)
	}
	var count int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func normalizeOverviewRange(value string, now time.Time) (string, string, time.Time, int64) {
	switch value {
	case "1h":
		return "1h", "최근 1시간", now.Add(-time.Hour), 300
	case "7d":
		return "7d", "최근 7일", now.Add(-7 * 24 * time.Hour), 43200
	default:
		return "24h", "최근 24시간", now.Add(-24 * time.Hour), 7200
	}
}

func (s *Store) Overview(ctx context.Context, filter OverviewFilter, now time.Time) (OverviewData, error) {
	rangeKey, rangeLabel, since, bucketSeconds := normalizeOverviewRange(filter.Range, now)
	filter.Range, filter.Since = rangeKey, since
	data := OverviewData{GeneratedAt: now.UTC(), Range: rangeKey, RangeLabel: rangeLabel, RangeStart: since.UTC(), RangeEnd: now.UTC()}

	servers, err := s.ListServers(ctx, filter.EnterpriseID, 5000)
	if err != nil {
		return OverviewData{}, err
	}
	groupMembers := map[string]bool(nil)
	if filter.GroupID != "" {
		groupMembers = make(map[string]bool)
		groups, groupErr := s.ListGroups(ctx, filter.EnterpriseID)
		if groupErr != nil {
			return OverviewData{}, groupErr
		}
		for _, group := range groups {
			if group.ID != filter.GroupID {
				continue
			}
			for _, member := range group.Members {
				groupMembers[member.ID] = true
			}
			break
		}
	}
	selectedServers := make(map[string]bool)
	for _, server := range servers {
		if filter.ServerID != "" && server.ID != filter.ServerID {
			continue
		}
		if groupMembers != nil && !groupMembers[server.ID] {
			continue
		}
		selectedServers[server.ID] = true
		if server.Revoked {
			continue
		}
		data.Summary.ActiveServers++
		if server.Status == "ONLINE" {
			data.Summary.OnlineServers++
		}
		if server.PolicyDeploymentStatus == "FAILED" || server.PackageDeploymentStatus == "FAILED" {
			data.Actions = append(data.Actions, OverviewAction{Kind: "deployment", Level: "danger", Title: "배포 실패", Detail: firstNonEmpty(server.PolicyDeploymentDetail, server.PackageDeploymentDetail, "정책 또는 패키지 배포 결과를 확인하세요."), TargetName: server.Name, URL: "/servers/" + server.ID})
		}
		if server.Status == "OFFLINE" {
			detail := "마지막 수신 시각을 확인할 수 없습니다."
			if server.LastHeartbeatAt.Valid {
				detail = fmt.Sprintf("마지막 수신 %s UTC", server.LastHeartbeatAt.Time.UTC().Format("2006-01-02 15:04"))
			}
			level := "warn"
			title := "Agent 오프라인"
			if !server.LastHeartbeatAt.Valid || now.Sub(server.LastHeartbeatAt.Time) >= 15*time.Minute {
				level, title = "danger", "장기간 미수신"
			}
			data.Actions = append(data.Actions, OverviewAction{Kind: "agent", Level: level, Title: title, Detail: detail, TargetName: server.Name, URL: "/servers/" + server.ID})
		}
	}

	where, args := overviewEventWhere(filter)
	countQuery := `SELECT COUNT(*),COALESCE(SUM(se.blocked),0) FROM security_events se JOIN servers s ON s.id=se.agent_id` + where
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&data.Summary.EventCount, &data.Summary.BlockedCount); err != nil {
		return OverviewData{}, err
	}
	if data.Summary.EventCount > 0 {
		data.Summary.BlockRate = float64(data.Summary.BlockedCount) * 100 / float64(data.Summary.EventCount)
	}

	seriesQuery := `SELECT FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(se.occurred_at)/?)*?),COUNT(*),COALESCE(SUM(se.blocked),0)
FROM security_events se JOIN servers s ON s.id=se.agent_id` + where + ` GROUP BY 1 ORDER BY 1`
	seriesArgs := append([]any{bucketSeconds, bucketSeconds}, args...)
	rows, err := s.db.QueryContext(ctx, seriesQuery, seriesArgs...)
	if err != nil {
		return OverviewData{}, err
	}
	for rows.Next() {
		var point OverviewPoint
		if err := rows.Scan(&point.At, &point.Events, &point.Blocked); err != nil {
			rows.Close()
			return OverviewData{}, err
		}
		data.Series = append(data.Series, point)
	}
	if err := rows.Close(); err != nil {
		return OverviewData{}, err
	}

	data.TopRules, err = s.overviewRanks(ctx, "se.rule_id", "se.rule_id<>''", "/events?rule_id=", where, args)
	if err != nil {
		return OverviewData{}, err
	}
	data.TopURIs, err = s.overviewRanks(ctx, "se.uri", "se.uri<>''", "/events?q=", where, args)
	if err != nil {
		return OverviewData{}, err
	}
	data.TopServers, err = s.overviewRanks(ctx, "se.agent_id", "se.agent_id<>''", "/events?server=", where, args)
	if err != nil {
		return OverviewData{}, err
	}
	for i := range data.TopServers {
		for _, server := range servers {
			if server.ID == data.TopServers[i].Key {
				data.TopServers[i].Label = server.Name
				break
			}
		}
	}

	eventFilter := EventFilter{EnterpriseID: filter.EnterpriseID, GroupID: filter.GroupID, ServerID: filter.ServerID, Since: since}
	data.Recent, err = s.ListEventsFiltered(ctx, "", eventFilter, 8)
	if err != nil {
		return OverviewData{}, err
	}

	policies, err := s.ListEnterprisePolicies(ctx, filter.EnterpriseID, 5000)
	if err != nil {
		return OverviewData{}, err
	}
	for _, policy := range policies {
		if filter.EnterpriseID != "" && policy.EnterpriseID != filter.EnterpriseID {
			continue
		}
		if filter.ServerID != "" || filter.GroupID != "" {
			winners, winnerErr := s.enterprisePolicyTargetsForOverview(ctx, policy, selectedServers)
			if winnerErr != nil {
				return OverviewData{}, winnerErr
			}
			if !winners {
				continue
			}
		}
		switch policy.LatestRolloutStatus {
		case "AWAITING_APPROVAL":
			data.Summary.PendingApproval++
			data.Actions = append(data.Actions, OverviewAction{Kind: "approval", Level: "warn", Title: "정책 승인 대기", Detail: "새 시스템 정책 개정본의 배포 승인이 필요합니다.", TargetName: policy.Name, URL: "/policies/" + policy.ID})
		case "FAILED", "PAUSED":
			data.Summary.FailedRollouts++
			data.Actions = append(data.Actions, OverviewAction{Kind: "rollout", Level: "danger", Title: "정책 단계 배포 실패", Detail: "실패 대상과 오류 요약을 확인한 뒤 재시도하세요.", TargetName: policy.Name, URL: "/policies/" + policy.ID})
		}
	}
	sort.SliceStable(data.Actions, func(i, j int) bool {
		priority := func(level string) int {
			if level == "danger" {
				return 0
			}
			return 1
		}
		return priority(data.Actions[i].Level) < priority(data.Actions[j].Level)
	})
	if len(data.Actions) > 20 {
		data.Actions = data.Actions[:20]
	}
	return data, nil
}

func overviewEventWhere(filter OverviewFilter) (string, []any) {
	conditions := []string{"se.occurred_at>=?"}
	args := []any{filter.Since.UTC()}
	if filter.EnterpriseID != "" {
		conditions = append(conditions, "s.enterprise_id=?")
		args = append(args, filter.EnterpriseID)
	}
	if filter.GroupID != "" {
		conditions = append(conditions, `EXISTS (SELECT 1 FROM server_group_members gm JOIN server_groups g ON g.id=gm.group_id WHERE gm.server_id=s.id AND g.id=? AND g.enterprise_id=s.enterprise_id)`)
		args = append(args, filter.GroupID)
	}
	if filter.ServerID != "" {
		conditions = append(conditions, "se.agent_id=?")
		args = append(args, filter.ServerID)
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) overviewRanks(ctx context.Context, field, extra, urlPrefix, where string, args []any) ([]OverviewRank, error) {
	query := `SELECT ` + field + `,` + field + `,COUNT(*),COALESCE(SUM(se.blocked),0) FROM security_events se JOIN servers s ON s.id=se.agent_id` + where + ` AND ` + extra + ` GROUP BY 1 ORDER BY 3 DESC LIMIT 5`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]OverviewRank, 0, 5)
	for rows.Next() {
		var item OverviewRank
		if err := rows.Scan(&item.Key, &item.Label, &item.Count, &item.Blocked); err != nil {
			return nil, err
		}
		item.URL = urlPrefix + url.QueryEscape(item.Key)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) enterprisePolicyTargetsForOverview(ctx context.Context, policy EnterprisePolicyRecord, selected map[string]bool) (bool, error) {
	_, ids, err := s.ResolvePolicyTarget(ctx, policy.EnterpriseID, policy.Target)
	if err != nil {
		return false, nil
	}
	for _, id := range ids {
		if selected[id] {
			return true, nil
		}
	}
	return false, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Store) EventByID(ctx context.Context, scopeEnterpriseID string, id uint64) (EventRecord, error) {
	query := `SELECT se.id,se.agent_id,s.name,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),se.occurred_at,se.transaction_id,se.service,se.method,se.uri,se.status_code,se.rule_id,se.message,se.severity,se.blocked,se.policy_revision,COALESCE(pr.enterprise_policy_id,'')
FROM security_events se JOIN servers s ON s.id=se.agent_id LEFT JOIN enterprises e ON e.id=s.enterprise_id
LEFT JOIN policy_revisions pr ON pr.id=se.policy_revision WHERE se.id=? AND (?='' OR s.enterprise_id=?)`
	var item EventRecord
	err := s.db.QueryRowContext(ctx, query, id, scopeEnterpriseID, scopeEnterpriseID).Scan(&item.ID, &item.AgentID, &item.ServerName, &item.EnterpriseID, &item.EnterpriseName, &item.OccurredAt, &item.TransactionID, &item.Service, &item.Method, &item.URI, &item.StatusCode, &item.RuleID, &item.Message, &item.Severity, &item.Blocked, &item.PolicyRevision, &item.PolicyID)
	return item, err
}

func (s *Store) TransactionEvents(ctx context.Context, scopeEnterpriseID string, event EventRecord) ([]EventRecord, error) {
	if event.TransactionID == "" {
		return []EventRecord{event}, nil
	}
	query := `SELECT se.id,se.agent_id,s.name,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),se.occurred_at,se.transaction_id,se.service,se.method,se.uri,se.status_code,se.rule_id,se.message,se.severity,se.blocked,se.policy_revision,COALESCE(pr.enterprise_policy_id,'')
FROM security_events se JOIN servers s ON s.id=se.agent_id LEFT JOIN enterprises e ON e.id=s.enterprise_id
LEFT JOIN policy_revisions pr ON pr.id=se.policy_revision
WHERE se.agent_id=? AND se.transaction_id=? AND (?='' OR s.enterprise_id=?) ORDER BY se.occurred_at,se.id LIMIT 100`
	rows, err := s.db.QueryContext(ctx, query, event.AgentID, event.TransactionID, scopeEnterpriseID, scopeEnterpriseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EventRecord, 0)
	for rows.Next() {
		var item EventRecord
		if err := rows.Scan(&item.ID, &item.AgentID, &item.ServerName, &item.EnterpriseID, &item.EnterpriseName, &item.OccurredAt, &item.TransactionID, &item.Service, &item.Method, &item.URI, &item.StatusCode, &item.RuleID, &item.Message, &item.Severity, &item.Blocked, &item.PolicyRevision, &item.PolicyID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type AuditLogRecord struct {
	ID         uint64
	RequestID  string
	Actor      string
	Action     string
	Target     string
	Result     string
	RemoteAddr string
	CreatedAt  time.Time
}

type AuditLogFilter struct {
	Actor  string
	Action string
	Result string
	Since  time.Time
	Offset int
}

func (s *Store) ListAuditLogs(ctx context.Context, filter AuditLogFilter, limit int) ([]AuditLogRecord, error) {
	query := `SELECT id,request_id,actor,action,target,result,remote_addr,created_at FROM admin_audit_logs`
	conditions := make([]string, 0, 4)
	args := make([]any, 0, 7)
	if filter.Actor != "" {
		conditions = append(conditions, "actor LIKE ?")
		args = append(args, "%"+filter.Actor+"%")
	}
	if filter.Action != "" {
		conditions = append(conditions, "action LIKE ?")
		args = append(args, "%"+filter.Action+"%")
	}
	if filter.Result != "" {
		conditions = append(conditions, "result=?")
		args = append(args, filter.Result)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "created_at>=?")
		args = append(args, filter.Since.UTC())
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, max(filter.Offset, 0))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AuditLogRecord, 0)
	for rows.Next() {
		var item AuditLogRecord
		if err := rows.Scan(&item.ID, &item.RequestID, &item.Actor, &item.Action, &item.Target, &item.Result, &item.RemoteAddr, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type AgentCommandRecord struct {
	ID              string
	Command         string
	Status          string
	Detail          string
	RequestedBy     string
	RequestedByName string
	CreatedAt       time.Time
	AcknowledgedAt  sql.NullTime
	CompletedAt     sql.NullTime
	UpdatedAt       time.Time
}

func (c AgentCommandRecord) StatusLabel() string { return statusLabel(c.Status) }
func (c AgentCommandRecord) StatusClass() string { return statusClass(c.Status) }
func (c AgentCommandRecord) CommandLabel() string {
	switch c.Command {
	case "agent_restart":
		return "Agent 재시작"
	case "agent_stop":
		return "Agent 중지"
	case "server_restart":
		return "서버 재시작"
	case "server_stop":
		return "서버 종료"
	default:
		return c.Command
	}
}

func (s *Store) ListServerCommands(ctx context.Context, scopeEnterpriseID, serverID string, limit int) ([]AgentCommandRecord, error) {
	query := `SELECT c.id,c.command,c.status,c.detail,c.requested_by,COALESCE(u.display_name,u.username,''),c.created_at,c.acknowledged_at,c.completed_at,c.updated_at
FROM agent_commands c JOIN servers s ON s.id=c.server_id LEFT JOIN admin_users u ON u.id=c.requested_by
WHERE c.server_id=? AND (?='' OR s.enterprise_id=?) ORDER BY c.created_at DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, serverID, scopeEnterpriseID, scopeEnterpriseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentCommandRecord, 0)
	for rows.Next() {
		var item AgentCommandRecord
		if err := rows.Scan(&item.ID, &item.Command, &item.Status, &item.Detail, &item.RequestedBy, &item.RequestedByName, &item.CreatedAt, &item.AcknowledgedAt, &item.CompletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
