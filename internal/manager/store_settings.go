package manager

import (
	"context"
	"errors"
	"strconv"
	"time"
)

const (
	eventRetentionKey = "event_retention_days"
	auditRetentionKey = "audit_retention_days"
)

type LogRetentionSettings struct {
	EventDays int
	AuditDays int
}

func DefaultLogRetentionSettings(eventRetention time.Duration) LogRetentionSettings {
	eventDays := int(eventRetention / (24 * time.Hour))
	if eventDays < 1 {
		eventDays = 30
	} else if eventDays > 3650 {
		eventDays = 3650
	}
	return LogRetentionSettings{EventDays: eventDays, AuditDays: 365}
}

func (s LogRetentionSettings) Valid() bool {
	return s.EventDays >= 1 && s.EventDays <= 3650 && s.AuditDays >= 30 && s.AuditDays <= 3650
}

func (s *Store) LogRetentionSettings(ctx context.Context, fallback LogRetentionSettings) (LogRetentionSettings, error) {
	settings := fallback
	rows, err := s.db.QueryContext(ctx, `SELECT setting_key,setting_value FROM system_settings WHERE setting_key IN (?,?)`, eventRetentionKey, auditRetentionKey)
	if err != nil {
		return settings, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return settings, err
		}
		days, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		switch key {
		case eventRetentionKey:
			settings.EventDays = days
		case auditRetentionKey:
			settings.AuditDays = days
		}
	}
	if err := rows.Err(); err != nil {
		return settings, err
	}
	if !settings.Valid() {
		return fallback, errors.New("invalid log retention settings")
	}
	return settings, nil
}

func (s *Store) UpdateLogRetentionSettings(ctx context.Context, settings LogRetentionSettings, updaterID string) error {
	if !settings.Valid() || updaterID == "" {
		return errors.New("invalid log retention settings")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `INSERT INTO system_settings(setting_key,setting_value,updated_by) VALUES (?,?,?)
ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value),updated_by=VALUES(updated_by)`
	for key, days := range map[string]int{eventRetentionKey: settings.EventDays, auditRetentionKey: settings.AuditDays} {
		if _, err := tx.ExecContext(ctx, query, key, strconv.Itoa(days), updaterID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PruneAuditLogs(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, errors.New("prune limit must be between 1 and 10000")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM admin_audit_logs WHERE created_at < ? ORDER BY created_at LIMIT ?`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
