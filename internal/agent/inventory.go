package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/config"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/policybundle"
	"github.com/Fhwang0926/m-waf/internal/version"
)

func CollectInventory(ctx context.Context, cfg config.Agent) (model.Inventory, error) {
	osRelease, err := readOSRelease("/etc/os-release")
	if err != nil {
		return model.Inventory{}, err
	}
	hostname, _ := os.Hostname()
	candidates := discoverWebServers(ctx)
	webServer, webServerBinary := cfg.WebServer, cfg.WebServerBinary
	webServerControl := model.WebServerControlStandard
	integrationMode, installationMode := cfg.IntegrationMode, cfg.InstallationMode
	if recorded, ok := readInstallationSelection(cfg.StateDirectory); ok {
		webServer, webServerBinary = recorded.WebServer, recorded.WebServerBinary
		webServerControl = model.NormalizeWebServerControl(recorded.WebServerControl)
		integrationMode, installationMode = recorded.IntegrationMode, recorded.InstallationMode
	} else if webServer == "" && installationMode != model.InstallationModeDiscovery && len(candidates) == 1 {
		webServer, webServerBinary = candidates[0].Kind, candidates[0].Binary
	}
	webVersion, webBuild := "", ""
	if webServer != "" {
		webVersion, webBuild, err = webServerInfo(ctx, webServer, webServerBinary)
		if err != nil {
			return model.Inventory{}, err
		}
	}
	moduleName := "mwaf-modsecurity-" + webServer
	if integrationMode == model.IntegrationModeExternal {
		moduleName += "-external"
	}
	moduleVersion := "unknown"
	if installationMode == model.InstallationModeCustomZIP {
		moduleVersion = readFirst(filepath.Join(cfg.StateDirectory, "custom-module.version"))
	} else if webServer != "" {
		moduleVersion = installedPackageVersion(ctx, moduleName)
	}
	connectorVersion := "unknown"
	if webServer != "" {
		connectorVersion = installedConnectorVersion(ctx, webServer)
	}
	if installationMode == "manual" {
		moduleVersion = "manual"
		if recorded := readFirst(filepath.Join(cfg.StateDirectory, "connector.version")); recorded != "unknown" {
			connectorVersion = recorded
		}
	}
	connectorLoaded, configTestOK, integrationReady := false, false, false
	if webServer != "" {
		connectorLoaded, configTestOK, integrationReady = connectorStatus(ctx, webServer, webServerBinary, webServerControl, cfg.PolicyPath)
	}
	crsVersion := appliedCRSVersion(cfg.PolicyPath)
	stage := model.InstallationStagePlanRequired
	if webServer != "" && moduleVersion != "unknown" {
		stage = model.InstallationStageIntegrationNeeded
	}
	if connectorLoaded && configTestOK && integrationReady && crsVersion != "unknown" {
		stage = model.InstallationStageProtected
	}
	return model.Inventory{
		Hostname: hostname, OSID: osRelease["ID"], OSVersion: osRelease["VERSION_ID"], Architecture: runtime.GOARCH,
		WebServer: webServer, WebServerVersion: webVersion, WebServerBuild: webBuild, IntegrationMode: integrationMode,
		InstallationMode: installationMode, AgentVersion: version.Version, ModuleVersion: moduleVersion, CRSVersion: crsVersion,
		ConnectorVersion: connectorVersion, ConnectorLoaded: connectorLoaded, ConfigTestOK: configTestOK, IntegrationReady: integrationReady,
		InstallationStage: stage, WebServerControl: webServerControl, WebServerCandidates: candidates,
		PolicyFormats: []string{"conf-v1", policybundle.Format, policybundle.FormatV3},
	}, nil
}

type installationSelection struct {
	WebServer        string `json:"web_server"`
	WebServerBinary  string `json:"web_server_binary"`
	WebServerControl string `json:"web_server_control,omitempty"`
	IntegrationMode  string `json:"integration_mode"`
	InstallationMode string `json:"installation_mode"`
}

func readInstallationSelection(stateDirectory string) (installationSelection, bool) {
	raw, err := os.ReadFile(filepath.Join(stateDirectory, "installation-selection.json"))
	if err != nil {
		return installationSelection{}, false
	}
	var selected installationSelection
	if json.Unmarshal(raw, &selected) != nil || (selected.WebServer != "apache" && selected.WebServer != "nginx") || !filepath.IsAbs(selected.WebServerBinary) {
		return installationSelection{}, false
	}
	selected.WebServerControl = model.NormalizeWebServerControl(selected.WebServerControl)
	if selected.WebServerControl != model.WebServerControlStandard && selected.WebServerControl != model.WebServerControlHooks {
		return installationSelection{}, false
	}
	return selected, true
}

func discoverWebServers(ctx context.Context) []model.WebServerCandidate {
	definitions := []struct {
		kind  string
		names []string
	}{
		{kind: "apache", names: []string{"apachectl", "httpd"}},
		{kind: "nginx", names: []string{"nginx"}},
	}
	running := runningWebServerBinaries()
	result := make([]model.WebServerCandidate, 0, len(definitions))
	seen := make(map[string]bool)
	for _, definition := range definitions {
		binaries := append([]string(nil), running[definition.kind]...)
		for _, name := range definition.names {
			if found, err := exec.LookPath(name); err == nil {
				absolute, _ := filepath.Abs(found)
				binaries = append(binaries, absolute)
			}
		}
		for _, binary := range binaries {
			if binary == "" || seen[definition.kind+":"+binary] {
				continue
			}
			seen[definition.kind+":"+binary] = true
			versionText, buildHash, infoErr := webServerInfo(ctx, definition.kind, binary)
			if infoErr != nil {
				continue
			}
			_, configOK, _ := connectorStatus(ctx, definition.kind, binary, model.WebServerControlStandard, "")
			result = append(result, model.WebServerCandidate{Kind: definition.kind, Version: versionText, BuildHash: buildHash, Binary: binary, PackageManaged: packageOwnsBinary(ctx, binary), ConfigTestOK: configOK})
		}
	}
	compact := make([]model.WebServerCandidate, 0, len(result))
	byBuild := make(map[string]int)
	for _, candidate := range result {
		key := candidate.Kind + ":" + candidate.BuildHash
		if index, exists := byBuild[key]; exists {
			if !compact[index].ConfigTestOK && candidate.ConfigTestOK {
				compact[index] = candidate
			}
			continue
		}
		byBuild[key] = len(compact)
		compact = append(compact, candidate)
	}
	return compact
}

func runningWebServerBinaries() map[string][]string {
	result := map[string][]string{"apache": {}, "nginx": {}}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		binary, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil || !filepath.IsAbs(binary) {
			continue
		}
		kind := ""
		switch filepath.Base(strings.TrimSuffix(binary, " (deleted)")) {
		case "apache2", "httpd":
			kind = "apache"
		case "nginx":
			kind = "nginx"
		}
		key := kind + ":" + binary
		if kind != "" && !seen[key] {
			seen[key] = true
			result[kind] = append(result[kind], binary)
		}
	}
	return result
}

func packageOwnsBinary(ctx context.Context, binary string) bool {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(checkCtx, "dpkg-query", "-S", binary).Run() == nil
}

func readOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if result["ID"] == "" || result["VERSION_ID"] == "" {
		return nil, errors.New("os-release ID and VERSION_ID are required")
	}
	return result, nil
}

func detectWebServer() (string, error) {
	_, nginxErr := exec.LookPath("nginx")
	_, apacheErr := exec.LookPath("apachectl")
	if apacheErr != nil {
		_, apacheErr = exec.LookPath("httpd")
	}
	if nginxErr == nil && apacheErr == nil {
		return "", errors.New("both Apache and Nginx are installed; set web_server")
	}
	if nginxErr == nil {
		return "nginx", nil
	}
	if apacheErr == nil {
		return "apache", nil
	}
	return "", errors.New("Apache or Nginx is required")
}

func webServerInfo(parent context.Context, kind, configuredBinary string) (string, string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	var command string
	var versionArgs, buildArgs []string
	switch kind {
	case "nginx":
		command, versionArgs, buildArgs = configuredBinary, []string{"-v"}, []string{"-V"}
		if command == "" {
			command = "nginx"
		}
	case "apache":
		command = configuredBinary
		if command == "" {
			command = "apachectl"
			if _, err := exec.LookPath(command); err != nil {
				command = "httpd"
			}
		}
		versionArgs, buildArgs = []string{"-v"}, []string{"-V"}
	default:
		return "", "", errors.New("unsupported web server")
	}
	versionOutput, err := exec.CommandContext(ctx, command, versionArgs...).CombinedOutput()
	if err != nil {
		return "", "", err
	}
	buildOutput, err := exec.CommandContext(ctx, command, buildArgs...).CombinedOutput()
	if err != nil {
		return "", "", err
	}
	versionText := string(versionOutput)
	if kind == "nginx" {
		if _, tail, ok := strings.Cut(versionText, "nginx/"); ok {
			versionText = strings.Fields(tail)[0]
		}
	} else if _, tail, ok := strings.Cut(versionText, "Apache/"); ok {
		versionText = strings.Fields(tail)[0]
	}
	sum := sha256.Sum256(normalizeBuildOutput(buildOutput))
	return strings.TrimSpace(versionText), hex.EncodeToString(sum[:]), nil
}

func normalizeBuildOutput(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "AH00558:") {
			continue
		}
		normalized = append(normalized, line)
	}
	return []byte(strings.Join(normalized, "\n") + "\n")
}

func installedPackageVersion(ctx context.Context, name string) string {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		output, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", name).Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		output, err := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name).Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "unknown"
}

func installedConnectorVersion(ctx context.Context, webServer string) string {
	names := []string{"libmodsecurity3"}
	if webServer == "apache" {
		names = []string{"libapache2-mod-security2"}
	} else if webServer == "nginx" {
		names = []string{"libnginx-mod-http-modsecurity", "libmodsecurity3"}
	}
	for _, name := range names {
		if version := installedPackageVersion(ctx, name); version != "unknown" {
			return version
		}
	}
	return "unknown"
}

func connectorStatus(parent context.Context, webServer, configuredBinary, controlMode, policyPath string) (bool, bool, bool) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	binary := configuredBinary
	if binary == "" {
		binary = webServer
		if webServer == "apache" {
			binary = "apachectl"
			if _, err := exec.LookPath(binary); err != nil {
				binary = "httpd"
			}
		}
	}
	configTestOK := false
	if model.NormalizeWebServerControl(controlMode) == model.WebServerControlHooks {
		if validateControlHooks(webServer) == nil {
			configTestOK = runControlHook(ctx, webServer, "configtest", binary, policyPath) == nil
		}
	} else {
		configTestOK = exec.CommandContext(ctx, binary, "-t").Run() == nil
	}
	if !configTestOK {
		return false, false, false
	}
	if webServer == "apache" {
		if binary == "" {
			return false, false, false
		}
		output, err := exec.CommandContext(ctx, binary, "-M").CombinedOutput()
		includes, includeErr := exec.CommandContext(ctx, binary, "-t", "-D", "DUMP_INCLUDES").CombinedOutput()
		ready := includeErr == nil && (strings.Contains(string(includes), "/etc/mwaf/") || strings.Contains(string(includes), "/opt/m-waf/"))
		return err == nil && strings.Contains(string(output), "security2_module"), true, ready
	}
	if webServer == "nginx" {
		output, err := exec.CommandContext(ctx, binary, "-T").CombinedOutput()
		loaded := err == nil && (strings.Contains(string(output), "modsecurity on;") || strings.Contains(string(output), "modsecurity_rules_file"))
		ready := err == nil && (strings.Contains(string(output), "/etc/mwaf/") || strings.Contains(string(output), "/opt/m-waf/"))
		return loaded, true, ready
	}
	return false, false, false
}

func readFirst(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(raw))
}

func appliedCRSVersion(policyPath string) string {
	manifestPath := filepath.Join(filepath.Dir(policyPath), "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest struct {
			PolicySource struct {
				Tag string `json:"tag"`
			} `json:"policy_source"`
		}
		if json.Unmarshal(raw, &manifest) == nil && manifest.PolicySource.Tag != "" {
			return strings.TrimPrefix(manifest.PolicySource.Tag, "v")
		}
	}
	return readFirst("/etc/mwaf/crs.version")
}
