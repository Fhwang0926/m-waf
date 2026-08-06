package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/manager"
	"github.com/Fhwang0926/m-waf/internal/version"
	"github.com/Fhwang0926/m-waf/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.LoadManager()
	if err != nil {
		logger.Error("load_config", "error", err)
		os.Exit(1)
	}
	store, err := manager.OpenStore(cfg.DBDSN)
	if err != nil {
		logger.Error("open_database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	startupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForDatabase(startupCtx, store); err != nil {
		logger.Error("database_unavailable", "error", err)
		os.Exit(1)
	}
	if cfg.DBMigrate {
		if err := migrations.Apply(startupCtx, store.DB()); err != nil {
			logger.Error("database_migration_failed", "error", err)
			os.Exit(1)
		}
	}

	app, err := manager.NewServer(cfg, store, logger)
	if err != nil {
		logger.Error("initialize_manager", "error", err)
		os.Exit(1)
	}
	if err := app.SyncCatalog(startupCtx); err != nil {
		logger.Warn("package_catalog_unavailable", "error", err)
	}
	cleanupCtx, stopCleanup := context.WithCancel(context.Background())
	defer stopCleanup()
	go runLogCleanup(cleanupCtx, cfg, store, logger)
	go runSystemPolicySync(cleanupCtx, cfg.PolicySyncInterval, app, logger)
	agentTLS, err := app.AgentTLSConfig()
	if err != nil {
		logger.Error("agent_tls_config", "error", err)
		os.Exit(1)
	}
	adminServer := &http.Server{
		Addr: cfg.AdminAddr, Handler: app.AdminHandler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	agentServer := &http.Server{
		Addr: cfg.AgentAddr, Handler: app.AgentHandler(), TLSConfig: agentTLS, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 90 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("admin_server_start", "addr", cfg.AdminAddr, "version", version.Version, "commit", version.Commit)
		errCh <- adminServer.ListenAndServeTLS(cfg.TLSCertificate, cfg.TLSPrivateKey)
	}()
	go func() {
		logger.Info("agent_server_start", "addr", cfg.AgentAddr, "version", version.Version, "commit", version.Commit)
		errCh <- agentServer.ListenAndServeTLS(cfg.TLSCertificate, cfg.TLSPrivateKey)
	}()

	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-signalCtx.Done():
		logger.Info("shutdown_signal")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http_server_failed", "error", err)
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	stopCleanup()
	_ = adminServer.Shutdown(shutdownCtx)
	_ = agentServer.Shutdown(shutdownCtx)
}

func runSystemPolicySync(ctx context.Context, interval time.Duration, app *manager.Server, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	syncPolicies := func() {
		syncCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if err := app.SyncSystemPolicies(syncCtx); err != nil {
			logger.Warn("system_policy_sync_failed", "error", err)
		}
	}
	syncPolicies()
	for {
		select {
		case <-ctx.Done():
			return
		case <-app.PolicySyncSignal():
			syncPolicies()
		case <-ticker.C:
			syncPolicies()
		}
	}
}

func runLogCleanup(ctx context.Context, cfg config.Manager, store *manager.Store, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.CleanupInterval)
	defer ticker.Stop()
	cleanup := func() {
		fallback := manager.DefaultLogRetentionSettings(cfg.EventRetention)
		settingsCtx, cancelSettings := context.WithTimeout(ctx, 10*time.Second)
		settings, err := store.LogRetentionSettings(settingsCtx, fallback)
		cancelSettings()
		if err != nil {
			logger.Warn("log_retention_settings_unavailable", "error", err)
			settings = fallback
		}
		now := time.Now().UTC()
		eventCtx, cancelEvents := context.WithTimeout(ctx, 2*time.Minute)
		eventDeleted, err := pruneInBatches(func() (int64, error) {
			return store.PruneEvents(eventCtx, now.AddDate(0, 0, -settings.EventDays), 5000)
		})
		cancelEvents()
		if err != nil {
			logger.Warn("event_cleanup_failed", "error", err)
		}
		batchCtx, cancelBatches := context.WithTimeout(ctx, 2*time.Minute)
		batchDeleted, err := pruneInBatches(func() (int64, error) {
			return store.PruneEventBatches(batchCtx, now.AddDate(0, 0, -settings.EventDays), 5000)
		})
		cancelBatches()
		if err != nil {
			logger.Warn("event_batch_cleanup_failed", "error", err)
		}
		auditCtx, cancelAudit := context.WithTimeout(ctx, 2*time.Minute)
		auditDeleted, err := pruneInBatches(func() (int64, error) {
			return store.PruneAuditLogs(auditCtx, now.AddDate(0, 0, -settings.AuditDays), 5000)
		})
		cancelAudit()
		if err != nil {
			logger.Warn("audit_cleanup_failed", "error", err)
		}
		if eventDeleted != 0 || batchDeleted != 0 || auditDeleted != 0 {
			logger.Info("log_cleanup", "events_deleted", eventDeleted, "event_batches_deleted", batchDeleted, "audit_logs_deleted", auditDeleted, "event_retention_days", settings.EventDays, "audit_retention_days", settings.AuditDays)
		}
	}
	cleanup()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func pruneInBatches(prune func() (int64, error)) (int64, error) {
	var total int64
	for {
		deleted, err := prune()
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted < 5000 {
			break
		}
	}
	return total, nil
}

func waitForDatabase(ctx context.Context, store *manager.Store) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := store.Ping(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
