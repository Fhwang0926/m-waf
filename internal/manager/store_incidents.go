package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const securityIncidentBackfillLock = "mwaf_security_incident_backfill_v1"

type IncidentFilter struct {
	EnterpriseID    string
	PolicyID        string
	ServerID        string
	Category        string
	Severity        string
	RuleID          string
	Query           string
	Blocked         *bool
	Since           time.Time
	CursorAt        time.Time
	CursorID        uint64
	CursorDirection string
	Offset          int
}

func insertIncidentTx(ctx context.Context, tx *sql.Tx, enterpriseID, serverID, key string, events []model.SecurityEvent) (uint64, error) {
	primary := selectPrimaryEvent(events)
	blocked := false
	for _, event := range events {
		blocked = blocked || event.Blocked
	}
	_, ip := canonicalEventIP(primary.ClientIP)
	country := strings.ToUpper(strings.TrimSpace(primary.CountryCode))
	if country == "" {
		country = "ZZ"
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO security_incidents(enterprise_id,agent_id,incident_key,occurred_at,category,client_ip,country_code,method,uri,status_code,blocked,policy_revision)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id),occurred_at=LEAST(occurred_at,VALUES(occurred_at)),
category=IF(FIELD(VALUES(category),'OTHER','HTTP_PROTOCOL','SCANNER_BOT','FILE_PATH','INJECTION','XSS')>FIELD(category,'OTHER','HTTP_PROTOCOL','SCANNER_BOT','FILE_PATH','INJECTION','XSS'),VALUES(category),category),
client_ip=COALESCE(client_ip,VALUES(client_ip)),country_code=IF(country_code='ZZ',VALUES(country_code),country_code),blocked=(blocked OR VALUES(blocked)),
policy_revision=IF(policy_revision='',VALUES(policy_revision),policy_revision)`, enterpriseID, serverID, key, primary.OccurredAt.UTC(), classifySecurityEvent(primary), ip, country, primary.Method, primary.URI, primary.StatusCode, blocked, primary.PolicyRevision)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	return uint64(id), err
}

func (s *Store) ListIncidents(ctx context.Context, scopeEnterpriseID string, filter IncidentFilter, limit int) ([]IncidentRecord, error) {
	query := `SELECT si.id,si.enterprise_id,COALESCE(e.name,'미지정'),si.agent_id,s.name,si.incident_key,si.occurred_at,si.category,si.client_ip,si.country_code,si.method,si.uri,si.status_code,si.blocked,COALESCE(si.primary_event_id,0),si.policy_revision,COALESCE(pr.enterprise_policy_id,''),COALESCE(pe.matched_variable,''),COALESCE(pe.rule_id,''),COALESCE(pe.message,'')
FROM security_incidents si JOIN servers s ON s.id=si.agent_id JOIN enterprises e ON e.id=si.enterprise_id
LEFT JOIN policy_revisions pr ON pr.id=si.policy_revision LEFT JOIN security_events pe ON pe.id=si.primary_event_id`
	conditions := make([]string, 0, 8)
	args := make([]any, 0, 12)
	if scopeEnterpriseID != "" {
		conditions = append(conditions, "si.enterprise_id=?")
		args = append(args, scopeEnterpriseID)
	} else if filter.EnterpriseID != "" {
		conditions = append(conditions, "si.enterprise_id=?")
		args = append(args, filter.EnterpriseID)
	}
	if filter.PolicyID != "" {
		conditions = append(conditions, `pr.enterprise_policy_id=? AND EXISTS (SELECT 1 FROM enterprise_policies ep WHERE ep.id=pr.enterprise_policy_id AND ep.enterprise_id=si.enterprise_id)`)
		args = append(args, filter.PolicyID)
	}
	if filter.ServerID != "" {
		conditions = append(conditions, "si.agent_id=?")
		args = append(args, filter.ServerID)
	}
	if filter.Category != "" {
		conditions = append(conditions, "si.category=?")
		args = append(args, filter.Category)
	}
	if filter.Severity != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM security_events fe WHERE fe.incident_id=si.id AND fe.severity=?)")
		args = append(args, filter.Severity)
	}
	if filter.RuleID != "" {
		conditions = append(conditions, "EXISTS (SELECT 1 FROM security_events fe WHERE fe.incident_id=si.id AND fe.rule_id=?)")
		args = append(args, filter.RuleID)
	}
	if filter.Blocked != nil {
		conditions = append(conditions, "si.blocked=?")
		args = append(args, *filter.Blocked)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "si.occurred_at>=?")
		args = append(args, filter.Since.UTC())
	}
	if filter.Query != "" {
		conditions = append(conditions, "(si.uri LIKE ? OR INET6_NTOA(si.client_ip) LIKE ? OR pe.message LIKE ?)")
		value := "%" + filter.Query + "%"
		args = append(args, value, value, value)
	}
	if !filter.CursorAt.IsZero() && filter.CursorID != 0 {
		operator := "<"
		if filter.CursorDirection == eventCursorAfter {
			operator = ">"
		}
		conditions = append(conditions, "(si.occurred_at "+operator+" ? OR (si.occurred_at=? AND si.id "+operator+" ?))")
		args = append(args, filter.CursorAt.UTC(), filter.CursorAt.UTC(), filter.CursorID)
		filter.Offset = 0
	}
	if len(conditions) != 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	order := "DESC"
	if filter.CursorDirection == eventCursorAfter {
		order = "ASC"
	}
	query += " ORDER BY si.occurred_at " + order + ",si.id " + order + " LIMIT ? OFFSET ?"
	args = append(args, limit, max(filter.Offset, 0))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]IncidentRecord, 0)
	for rows.Next() {
		var item IncidentRecord
		var rawIP []byte
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.AgentID, &item.ServerName, &item.IncidentKey, &item.OccurredAt, &item.Category, &rawIP, &item.CountryCode, &item.Method, &item.URI, &item.StatusCode, &item.Blocked, &item.PrimaryEventID, &item.PolicyRevision, &item.PolicyID, &item.MatchedVariable, &item.PrimaryRuleID, &item.PrimaryMessage); err != nil {
			return nil, err
		}
		item.ClientIP = displayStoredIP(rawIP)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) IncidentByID(ctx context.Context, scopeEnterpriseID string, id uint64) (IncidentRecord, error) {
	query := `SELECT si.id,si.enterprise_id,COALESCE(e.name,'미지정'),si.agent_id,s.name,si.incident_key,si.occurred_at,si.category,si.client_ip,si.country_code,si.method,si.uri,si.status_code,si.blocked,COALESCE(si.primary_event_id,0),si.policy_revision,COALESCE(pr.enterprise_policy_id,''),COALESCE(pe.matched_variable,''),COALESCE(pe.rule_id,''),COALESCE(pe.message,'')
FROM security_incidents si JOIN servers s ON s.id=si.agent_id JOIN enterprises e ON e.id=si.enterprise_id
LEFT JOIN policy_revisions pr ON pr.id=si.policy_revision LEFT JOIN security_events pe ON pe.id=si.primary_event_id
WHERE si.id=? AND (?='' OR si.enterprise_id=?)`
	var item IncidentRecord
	var rawIP []byte
	err := s.db.QueryRowContext(ctx, query, id, scopeEnterpriseID, scopeEnterpriseID).Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.AgentID, &item.ServerName, &item.IncidentKey, &item.OccurredAt, &item.Category, &rawIP, &item.CountryCode, &item.Method, &item.URI, &item.StatusCode, &item.Blocked, &item.PrimaryEventID, &item.PolicyRevision, &item.PolicyID, &item.MatchedVariable, &item.PrimaryRuleID, &item.PrimaryMessage)
	if err != nil {
		return IncidentRecord{}, err
	}
	item.ClientIP = displayStoredIP(rawIP)
	item.Events, err = s.IncidentEvents(ctx, scopeEnterpriseID, item.ID)
	return item, err
}

func (s *Store) IncidentEvents(ctx context.Context, scopeEnterpriseID string, incidentID uint64) ([]EventRecord, error) {
	query := `SELECT se.id,se.incident_id,se.request_id,se.agent_id,s.name,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),se.occurred_at,se.transaction_id,se.service,se.method,se.uri,se.client_ip,se.status_code,se.rule_id,se.message,se.matched_variable,se.rule_tags_json,se.severity,se.blocked,se.policy_revision,COALESCE(pr.enterprise_policy_id,'')
FROM security_events se JOIN servers s ON s.id=se.agent_id LEFT JOIN enterprises e ON e.id=s.enterprise_id LEFT JOIN policy_revisions pr ON pr.id=se.policy_revision
WHERE se.incident_id=? AND (?='' OR s.enterprise_id=?) ORDER BY se.id LIMIT 100`
	rows, err := s.db.QueryContext(ctx, query, incidentID, scopeEnterpriseID, scopeEnterpriseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EventRecord, 0)
	for rows.Next() {
		var item EventRecord
		var rawIP, tags []byte
		if err := rows.Scan(&item.ID, &item.IncidentID, &item.RequestID, &item.AgentID, &item.ServerName, &item.EnterpriseID, &item.EnterpriseName, &item.OccurredAt, &item.TransactionID, &item.Service, &item.Method, &item.URI, &rawIP, &item.StatusCode, &item.RuleID, &item.Message, &item.MatchedVariable, &tags, &item.Severity, &item.Blocked, &item.PolicyRevision, &item.PolicyID); err != nil {
			return nil, err
		}
		item.ClientIP = displayStoredIP(rawIP)
		_ = json.Unmarshal(tags, &item.RuleTags)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) PruneIncidents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, errors.New("prune limit must be between 1 and 10000")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM security_incidents WHERE occurred_at<? AND NOT EXISTS (SELECT 1 FROM security_events se WHERE se.incident_id=security_incidents.id) ORDER BY occurred_at LIMIT ?`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) BackfillSecurityIncidents(ctx context.Context) error {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	var locked int
	if err := connection.QueryRowContext(ctx, `SELECT GET_LOCK(?,0)`, securityIncidentBackfillLock).Scan(&locked); err != nil {
		return err
	}
	if locked != 1 {
		return nil
	}
	defer connection.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, securityIncidentBackfillLock)
	for {
		count, err := s.backfillSecurityIncidentBatch(ctx, 1000)
		if err != nil || count == 0 {
			return err
		}
	}
}

func (s *Store) backfillSecurityIncidentBatch(ctx context.Context, limit int) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT se.id,se.agent_id,s.enterprise_id,se.event_id,se.request_id,se.occurred_at,se.transaction_id,se.service,se.method,se.uri,se.status_code,se.rule_id,se.message,se.matched_variable,se.rule_tags_json,se.severity,se.blocked,se.policy_revision
FROM security_events se JOIN servers s ON s.id=se.agent_id WHERE se.incident_id IS NULL ORDER BY se.id LIMIT ?`, limit)
	if err != nil {
		return 0, err
	}
	type candidate struct {
		id, incidentID        uint64
		enterpriseID, agentID string
		event                 model.SecurityEvent
	}
	items := make([]candidate, 0, limit)
	for rows.Next() {
		var item candidate
		var tags []byte
		if err := rows.Scan(&item.id, &item.agentID, &item.enterpriseID, &item.event.EventID, &item.event.RequestID, &item.event.OccurredAt, &item.event.TransactionID, &item.event.Service, &item.event.Method, &item.event.URI, &item.event.StatusCode, &item.event.RuleID, &item.event.Message, &item.event.MatchedVariable, &tags, &item.event.Severity, &item.event.Blocked, &item.event.PolicyRevision); err != nil {
			rows.Close()
			return 0, err
		}
		_ = json.Unmarshal(tags, &item.event.RuleTags)
		items = append(items, item)
	}
	if err := rows.Close(); err != nil || len(items) == 0 {
		return len(items), err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	groups := make(map[string][]int)
	for index := range items {
		key := items[index].agentID + "\x00" + incidentKey(items[index].event)
		groups[key] = append(groups[key], index)
	}
	for _, indexes := range groups {
		events := make([]model.SecurityEvent, 0, len(indexes))
		for _, index := range indexes {
			events = append(events, items[index].event)
		}
		first := items[indexes[0]]
		incidentID, err := insertIncidentTx(ctx, tx, first.enterpriseID, first.agentID, incidentKey(first.event), events)
		if err != nil {
			return 0, err
		}
		for _, index := range indexes {
			items[index].incidentID = incidentID
		}
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `UPDATE security_events SET incident_id=? WHERE id=? AND incident_id IS NULL`, item.incidentID, item.id); err != nil {
			return 0, err
		}
	}
	for _, indexes := range groups {
		id := items[indexes[0]].incidentID
		if _, err := tx.ExecContext(ctx, `UPDATE security_incidents SET primary_event_id=(SELECT se.id FROM security_events se WHERE se.incident_id=? ORDER BY CASE WHEN se.rule_id LIKE '949%' OR se.rule_id LIKE '959%' OR se.rule_id LIKE '980%' THEN 1 ELSE 0 END,se.id LIMIT 1) WHERE id=?`, id, id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

func validateIncidentCategory(value string) bool {
	switch value {
	case "", AttackCategoryHTTPProtocol, AttackCategoryInjection, AttackCategoryXSS, AttackCategoryFilePath, AttackCategoryScannerBot, AttackCategoryOther:
		return true
	default:
		return false
	}
}

func incidentNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func incidentAuditTarget(incident IncidentRecord) string {
	return fmt.Sprintf("incident:%d:%s", incident.ID, incident.AgentID)
}

func (s *Store) PoliciesWithExpiredIPRules(ctx context.Context, now time.Time, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ep.id FROM enterprise_policies ep
JOIN policy_configurations pc ON pc.policy_revision_id=ep.current_revision_id
JOIN policy_configuration_ip_rules ip ON ip.configuration_id=pc.id
WHERE ep.status='ACTIVE' AND ip.enabled=TRUE AND ip.expires_at IS NOT NULL AND ip.expires_at<=? ORDER BY ep.id LIMIT ?`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	return items, rows.Err()
}

func (s *Store) PoliciesWithExpiredExceptions(ctx context.Context, now time.Time, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ep.id FROM enterprise_policies ep
JOIN policy_configurations pc ON pc.policy_revision_id=ep.current_revision_id
JOIN policy_configuration_exclusions pe ON pe.configuration_id=pc.id
WHERE ep.status='ACTIVE' AND pe.source_scope='ENTERPRISE' AND pe.enabled=TRUE AND pe.expires_at IS NOT NULL AND pe.expires_at<=? ORDER BY ep.id LIMIT ?`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	return items, rows.Err()
}
