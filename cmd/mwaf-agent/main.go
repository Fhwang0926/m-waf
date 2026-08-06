package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Fhwang0926/m-waf/internal/agent"
	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/version"
)

func main() {
	configPath := flag.String("config", "/etc/mwaf-agent/agent.json", "agent configuration path")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		println(version.Version, version.Commit)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.LoadAgent(*configPath)
	if err != nil {
		logger.Error("load_config", "error", err)
		os.Exit(1)
	}
	app, err := agent.New(cfg, logger)
	if err != nil {
		logger.Error("initialize_agent", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("agent_stopped", "error", err)
		os.Exit(1)
	}
}
