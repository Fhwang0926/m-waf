package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/manager"
)

func runSystemAdminPasswordReset(logger *slog.Logger, args []string, input io.Reader) error {
	flags := flag.NewFlagSet("reset-system-admin-password", flag.ContinueOnError)
	username := flags.String("username", "", "active system-administrator username")
	passwordStdin := flags.Bool("password-stdin", false, "read the new password from standard input")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *username == "" || !*passwordStdin {
		return errors.New("usage: mwaf-manager reset-system-admin-password --username USERNAME --password-stdin")
	}
	password, err := readRecoveryPassword(input)
	if err != nil {
		return err
	}
	if err := manager.ValidateSystemAdminRecoveryInput(*username, password); err != nil {
		return err
	}
	cfg, err := config.LoadManager()
	if err != nil {
		return fmt.Errorf("load manager configuration: %w", err)
	}
	store, err := manager.OpenStore(cfg.DBDSN)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForDatabase(ctx, store); err != nil {
		return fmt.Errorf("database unavailable: %w", err)
	}
	if err := manager.ResetSystemAdminPassword(ctx, store, *username, password); err != nil {
		return err
	}
	logger.Info("system_admin_password_reset", "username", *username)
	return nil
}

func readRecoveryPassword(input io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(raw) > 4096 {
		return "", errors.New("password input is too large")
	}
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	if len(raw) == 0 || bytes.ContainsAny(raw, "\r\n") {
		return "", errors.New("password file must contain exactly one password line")
	}
	return string(raw), nil
}
