package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func (a *Agent) applyPackageDeployment(parent context.Context, deployment model.PackageDeployment) error {
	if deployment.ID == "" || deployment.Agent.ID == "" || deployment.Module.ID == "" {
		return errors.New("package deployment is incomplete")
	}
	temporary, err := os.MkdirTemp(a.cfg.StateDirectory, ".packages-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	agentPath := filepath.Join(temporary, "agent.deb")
	modulePath := filepath.Join(temporary, "module.deb")
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	if err := a.client.DownloadPackage(ctx, deployment.Agent, agentPath); err != nil {
		return fmt.Errorf("download agent package: %w", err)
	}
	if err := a.client.DownloadPackage(ctx, deployment.Module, modulePath); err != nil {
		return fmt.Errorf("download module package: %w", err)
	}
	command := exec.CommandContext(ctx, "apt-get", "-o", "Dpkg::Options::=--force-confold", "install", "--no-install-recommends", "-y", modulePath, agentPath)
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install packages: %s: %w", truncateOperationOutput(output), err)
	}
	return nil
}

func restartUpdatedAgent() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "--no-block", "restart", "mwaf-agent.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart updated agent: %s: %w", truncateOperationOutput(output), err)
	}
	return nil
}

func (a *Agent) executeNextCommand(ctx context.Context) error {
	command, err := a.client.NextCommand(ctx)
	if err != nil || command.ID == "" {
		return err
	}
	lastID, err := readStateValue(filepath.Join(a.cfg.StateDirectory, "last-command-id"))
	if err != nil {
		return err
	}
	if lastID == command.ID {
		return a.client.SendCommandResult(ctx, command.ID, "ACCEPTED", "명령이 이미 Agent에 접수되었습니다.")
	}
	arguments, ok := fixedCommand(command.Command)
	if !ok {
		_ = a.client.SendCommandResult(ctx, command.ID, "FAILED", "지원하지 않는 고정 명령입니다.")
		return errors.New("unsupported manager command")
	}
	if err := a.client.SendCommandResult(ctx, command.ID, "ACCEPTED", "Agent가 고정 명령을 접수했습니다."); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "last-command-id"), []byte(command.ID+"\n"), 0o640); err != nil {
		_ = a.client.SendCommandResult(ctx, command.ID, "FAILED", "명령 실행 상태를 저장하지 못했습니다.")
		return err
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(operationCtx, arguments[0], arguments[1:]...).CombinedOutput()
	if err != nil {
		detail := "고정 명령 실행 실패: " + truncateOperationOutput(output)
		_ = a.client.SendCommandResult(ctx, command.ID, "FAILED", detail)
		return fmt.Errorf("execute %s: %s: %w", command.Command, truncateOperationOutput(output), err)
	}
	return nil
}

func fixedCommand(command string) ([]string, bool) {
	switch command {
	case "agent_restart":
		return []string{"systemctl", "--no-block", "restart", "mwaf-agent.service"}, true
	case "agent_stop":
		return []string{"systemctl", "--no-block", "stop", "mwaf-agent.service"}, true
	case "server_restart":
		return []string{"systemctl", "--no-block", "reboot"}, true
	case "server_stop":
		return []string{"systemctl", "--no-block", "poweroff"}, true
	default:
		return nil, false
	}
}

func readStateValue(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func truncateOperationOutput(raw []byte) string {
	const limit = 2048
	if len(raw) > limit {
		raw = raw[:limit]
	}
	return strings.TrimSpace(string(raw))
}
