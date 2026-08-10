package agent

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/version"
)

func (a *Agent) applyPackageDeployment(parent context.Context, deployment model.PackageDeployment) (bool, error) {
	if deployment.ID == "" || deployment.Agent.ID == "" || deployment.Module.ID == "" {
		return false, errors.New("package deployment is incomplete")
	}
	moduleFormat := deployment.Module.Format
	if moduleFormat == "" {
		moduleFormat = model.PackageFormatDEB
	}
	if moduleFormat != model.PackageFormatDEB && moduleFormat != model.PackageFormatZIP {
		return false, fmt.Errorf("unsupported module package format %q", moduleFormat)
	}
	if moduleFormat == model.PackageFormatZIP && (deployment.Module.WebServerBuild == "" || deployment.Module.RuntimeABI == "") {
		return false, errors.New("custom ZIP module metadata requires exact web-server build and runtime ABI")
	}
	selected, err := selectInstallationCandidate(parent, deployment.Module)
	if err != nil {
		return false, err
	}
	controlMode := model.NormalizeWebServerControl(deployment.WebServerControl)
	if controlMode != model.WebServerControlStandard && controlMode != model.WebServerControlHooks {
		return false, fmt.Errorf("unsupported web-server control mode %q", controlMode)
	}
	if controlMode == model.WebServerControlHooks {
		if err := validateControlHooks(selected.Kind); err != nil {
			return false, err
		}
	}
	temporary, err := os.MkdirTemp(a.cfg.StateDirectory, ".packages-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(temporary)
	agentPath := filepath.Join(temporary, "agent.deb")
	modulePath := filepath.Join(temporary, "module."+moduleFormat)
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	agentUpdated := deployment.Agent.Version != "" && deployment.Agent.Version != version.Version
	if agentUpdated {
		if err := a.client.DownloadPackage(ctx, deployment.Agent, agentPath); err != nil {
			return false, fmt.Errorf("download agent package: %w", err)
		}
	}
	if err := a.client.DownloadPackage(ctx, deployment.Module, modulePath); err != nil {
		return false, fmt.Errorf("download module package: %w", err)
	}
	if moduleFormat == model.PackageFormatZIP {
		if deployment.Module.InstallRoot != "/opt/m-waf" || deployment.Module.IntegrationMode != model.IntegrationModeExternal {
			return false, errors.New("custom ZIP modules require external integration under /opt/m-waf")
		}
		if err := installCustomModuleZIP(modulePath, deployment.Module); err != nil {
			return false, err
		}
		if err := ensurePolicyPlaceholder(a.cfg.PolicyPath); err != nil {
			return false, err
		}
		if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "custom-module.version"), []byte(deployment.Module.Version+"\n"), 0o640); err != nil {
			return false, err
		}
		if agentUpdated {
			if err := installDEBPackages(ctx, agentPath); err != nil {
				return false, err
			}
		}
	} else {
		paths := []string{modulePath}
		if agentUpdated {
			paths = append(paths, agentPath)
		}
		if err := installDEBPackages(ctx, paths...); err != nil {
			return false, err
		}
		if err := preparePackageIntegrationFiles(deployment.Module.WebServer); err != nil {
			return false, err
		}
	}
	selection := installationSelection{WebServer: deployment.Module.WebServer, WebServerBinary: selected.Binary, WebServerControl: controlMode, IntegrationMode: deployment.Module.IntegrationMode, InstallationMode: model.InstallationModePackage}
	if moduleFormat == model.PackageFormatZIP {
		selection.InstallationMode = model.InstallationModeCustomZIP
	}
	raw, err := json.Marshal(selection)
	if err != nil {
		return false, err
	}
	if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "installation-selection.json"), append(raw, '\n'), 0o640); err != nil {
		return false, err
	}
	return agentUpdated, nil
}

func controlHookPath(webServer, action string) string {
	return filepath.Join("/opt/m-waf/hooks", webServer, action)
}

func validateControlHooks(webServer string) error {
	if webServer != "apache" && webServer != "nginx" {
		return errors.New("control hooks require Apache or Nginx")
	}
	for _, directory := range []string{"/opt/m-waf", "/opt/m-waf/hooks", filepath.Join("/opt/m-waf/hooks", webServer)} {
		if err := validateRootControlledPath(directory, true); err != nil {
			return err
		}
	}
	for _, action := range []string{"configtest", "reload"} {
		path := controlHookPath(webServer, action)
		if err := validateRootControlledPath(path, false); err != nil {
			return err
		}
		info, _ := os.Lstat(path)
		if info.Mode().Perm()&0o100 == 0 {
			return fmt.Errorf("control hook %s is not executable by root", path)
		}
	}
	return nil
}

func validateRootControlledPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("control hook path %s is not ready: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("control hook path %s has an unsafe file type", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("control hook path %s must not be writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("control hook path %s must be owned by root", path)
	}
	return nil
}

func runControlHook(ctx context.Context, webServer, action, webServerBinary, policyPath string) error {
	path := controlHookPath(webServer, action)
	command := exec.CommandContext(ctx, path)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"MWAF_WEB_SERVER=" + webServer,
		"MWAF_WEB_SERVER_BINARY=" + webServerBinary,
		"MWAF_POLICY_PATH=" + policyPath,
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %s: %w", path, truncateOperationOutput(output), err)
	}
	return nil
}

func preparePackageIntegrationFiles(webServer string) error {
	if webServer != "nginx" {
		return nil
	}
	raw, err := os.ReadFile("/usr/share/mwaf/integration/modsecurity-nginx.conf")
	if err != nil {
		return fmt.Errorf("read packaged Nginx integration: %w", err)
	}
	destination := "/etc/mwaf/nginx/modsecurity.conf"
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	return atomicWrite(destination, raw, 0o640)
}

func ensurePolicyPlaceholder(policyPath string) error {
	if !filepath.IsAbs(policyPath) || filepath.Clean(policyPath) == string(filepath.Separator) {
		return errors.New("policy path is unsafe")
	}
	if _, err := os.Stat(policyPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o750); err != nil {
		return err
	}
	return atomicWrite(policyPath, []byte("# M-WAF unassigned safe policy.\nSecRuleEngine DetectionOnly\n"), 0o640)
}

func selectInstallationCandidate(ctx context.Context, item model.PackageDownload) (model.WebServerCandidate, error) {
	for _, candidate := range discoverWebServers(ctx) {
		if candidate.Kind != item.WebServer {
			continue
		}
		if item.WebServerBuild != "" && !strings.EqualFold(candidate.BuildHash, item.WebServerBuild) {
			continue
		}
		if item.Format == model.PackageFormatDEB && item.IntegrationMode == model.IntegrationModeDistro && !candidate.PackageManaged {
			continue
		}
		return candidate, nil
	}
	return model.WebServerCandidate{}, fmt.Errorf("selected %s build is no longer present on the server", item.WebServer)
}

func installDEBPackages(ctx context.Context, paths ...string) error {
	arguments := []string{"-o", "Dpkg::Options::=--force-confold", "install", "--no-install-recommends", "-y"}
	arguments = append(arguments, paths...)
	command := exec.CommandContext(ctx, "apt-get", arguments...)
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install packages: %s: %w", truncateOperationOutput(output), err)
	}
	return nil
}

type customModuleManifest struct {
	SchemaVersion  int    `json:"schema_version"`
	WebServer      string `json:"web_server"`
	Version        string `json:"version"`
	WebServerBuild string `json:"web_server_build_hash"`
	RuntimeABI     string `json:"runtime_abi"`
}

func installCustomModuleZIP(archivePath string, item model.PackageDownload) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open custom module ZIP: %w", err)
	}
	defer reader.Close()
	if len(reader.File) == 0 || len(reader.File) > 128 {
		return errors.New("custom module ZIP file count is invalid")
	}
	var manifest customModuleManifest
	manifestFound, moduleFound, integrationFound := false, false, false
	totalSize := uint64(0)
	entryNames := make(map[string]bool, len(reader.File))
	for _, entry := range reader.File {
		name := filepath.ToSlash(filepath.Clean(entry.Name))
		if entryNames[name] {
			return fmt.Errorf("custom module ZIP contains duplicate entry %q", name)
		}
		entryNames[name] = true
		if !entry.FileInfo().IsDir() {
			totalSize += entry.UncompressedSize64
			if totalSize > 512<<20 {
				return errors.New("custom module ZIP uncompressed size is too large")
			}
		}
		if name == "mwaf-module.json" {
			raw, readErr := readZIPEntry(entry, 64<<10)
			if readErr != nil || json.Unmarshal(raw, &manifest) != nil {
				return errors.New("custom module manifest is invalid")
			}
			manifestFound = true
		}
		moduleFound = moduleFound || strings.HasPrefix(name, "module/") && !entry.FileInfo().IsDir()
		integrationFound = integrationFound || name == "integration/mwaf.conf"
	}
	if !manifestFound || !moduleFound || !integrationFound || manifest.SchemaVersion != 1 || manifest.WebServer != item.WebServer || manifest.Version != item.Version || !strings.EqualFold(manifest.WebServerBuild, item.WebServerBuild) || manifest.RuntimeABI != item.RuntimeABI {
		return errors.New("custom module ZIP does not match the signed package metadata")
	}
	shortHash := item.SHA256
	if len(shortHash) > 12 {
		shortHash = shortHash[:12]
	}
	root := filepath.Join("/opt/m-waf/modules", item.WebServer)
	target := filepath.Join(root, item.Version+"-"+shortHash)
	if existing, statErr := os.ReadFile(filepath.Join(target, ".artifact-sha256")); statErr == nil && strings.TrimSpace(string(existing)) == item.SHA256 {
		return replaceCustomModuleLink(root, target)
	} else if statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("custom module destination already exists with different contents")
	}
	staging, err := os.MkdirTemp(root, ".staging-")
	if errors.Is(err, os.ErrNotExist) {
		if err = os.MkdirAll(root, 0o750); err == nil {
			staging, err = os.MkdirTemp(root, ".staging-")
		}
	}
	if err != nil {
		return fmt.Errorf("create custom module staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	for _, entry := range reader.File {
		name := filepath.ToSlash(filepath.Clean(entry.Name))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) || entry.Mode()&os.ModeSymlink != 0 || entry.Mode()&os.ModeType != 0 && !entry.FileInfo().IsDir() {
			return fmt.Errorf("unsafe custom module ZIP entry %q", entry.Name)
		}
		destination := filepath.Join(staging, filepath.FromSlash(name))
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0o750); err != nil {
				return err
			}
			continue
		}
		if entry.UncompressedSize64 > 256<<20 {
			return fmt.Errorf("custom module ZIP entry %q is too large", entry.Name)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			return err
		}
		raw, err := readZIPEntry(entry, 256<<20)
		if err != nil {
			return err
		}
		mode := entry.Mode().Perm() & 0o755
		if mode == 0 {
			mode = 0o640
		}
		if err := atomicWrite(destination, raw, mode); err != nil {
			return err
		}
	}
	if err := atomicWrite(filepath.Join(staging, ".artifact-sha256"), []byte(item.SHA256+"\n"), 0o640); err != nil {
		return err
	}
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("publish custom module: %w", err)
	}
	return replaceCustomModuleLink(root, target)
}

func readZIPEntry(entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	limited := io.LimitReader(reader, limit+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("custom module ZIP entry exceeds its size limit")
	}
	return raw, nil
}

func replaceCustomModuleLink(root, target string) error {
	current := filepath.Join(root, "current")
	temporary := current + ".next"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, current); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func restartUpdatedAgent() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	arguments, ok := agentServiceCommand("restart")
	if !ok {
		return errors.New("restart updated agent: no supported Agent service manager is running")
	}
	output, err := exec.CommandContext(ctx, arguments[0], arguments[1:]...).CombinedOutput()
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
	if handled, detail, controlErr := a.applyWebServerControlCommand(command.Command); handled {
		if controlErr != nil {
			_ = a.client.SendCommandResult(ctx, command.ID, "FAILED", controlErr.Error())
			return controlErr
		}
		if err := a.client.SendCommandResult(ctx, command.ID, "ACCEPTED", detail); err != nil {
			return err
		}
		if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "last-command-id"), []byte(command.ID+"\n"), 0o640); err != nil {
			return fmt.Errorf("save completed command: %w", err)
		}
		return nil
	}
	arguments, ok := fixedCommand(command.Command)
	if !ok {
		_ = a.client.SendCommandResult(ctx, command.ID, "FAILED", "지원하지 않는 고정 명령입니다.")
		return errors.New("unsupported manager command")
	}
	if err := a.client.SendCommandResult(ctx, command.ID, "ACCEPTED", "Agent가 고정 명령을 접수했습니다."); err != nil {
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
	if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "last-command-id"), []byte(command.ID+"\n"), 0o640); err != nil {
		return fmt.Errorf("save completed command: %w", err)
	}
	return nil
}

func (a *Agent) applyWebServerControlCommand(command string) (bool, string, error) {
	controlMode := ""
	label := ""
	switch command {
	case "web_control_standard":
		controlMode, label = model.WebServerControlStandard, "표준 웹서버 제어를 사용합니다."
	case "web_control_hooks":
		controlMode, label = model.WebServerControlHooks, "검증된 고객 Hook을 사용합니다."
	default:
		return false, "", nil
	}
	selection, ok := readInstallationSelection(a.cfg.StateDirectory)
	if !ok {
		return true, "", errors.New("웹서버 설치 선택이 없어 제어 방식을 변경할 수 없습니다")
	}
	if controlMode == model.WebServerControlHooks {
		if err := validateControlHooks(selection.WebServer); err != nil {
			return true, "", err
		}
	}
	selection.WebServerControl = controlMode
	raw, err := json.Marshal(selection)
	if err != nil {
		return true, "", err
	}
	if err := atomicWrite(filepath.Join(a.cfg.StateDirectory, "installation-selection.json"), append(raw, '\n'), 0o640); err != nil {
		return true, "", err
	}
	return true, label, nil
}

func fixedCommand(command string) ([]string, bool) {
	switch command {
	case "agent_restart":
		return agentServiceCommand("restart")
	case "agent_stop":
		return agentServiceCommand("stop")
	case "server_restart":
		if systemdRunning() {
			return []string{"systemctl", "--no-block", "reboot"}, true
		}
		return nil, false
	case "server_stop":
		if systemdRunning() {
			return []string{"systemctl", "--no-block", "poweroff"}, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func agentServiceCommand(action string) ([]string, bool) {
	const serviceCommand = "/usr/sbin/mwaf-agent-service"
	info, err := os.Lstat(serviceCommand)
	stat, ownedByRoot := infoSysStat(info)
	if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o111 != 0 && info.Mode().Perm()&0o022 == 0 && ownedByRoot && stat.Uid == 0 {
		return []string{serviceCommand, action}, true
	}
	return nil, false
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func systemdRunning() bool {
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
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
