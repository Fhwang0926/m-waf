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
	webServer := cfg.WebServer
	if webServer == "" {
		webServer, err = detectWebServer()
		if err != nil {
			return model.Inventory{}, err
		}
	}
	webVersion, webBuild, err := webServerInfo(ctx, webServer, cfg.WebServerBinary)
	if err != nil {
		return model.Inventory{}, err
	}
	moduleName := "mwaf-modsecurity-" + webServer
	if cfg.IntegrationMode == "external" {
		moduleName += "-external"
	}
	moduleVersion := installedPackageVersion(ctx, moduleName)
	connectorVersion := installedConnectorVersion(ctx, webServer)
	if cfg.InstallationMode == "manual" {
		moduleVersion = "manual"
		if recorded := readFirst(filepath.Join(cfg.StateDirectory, "connector.version")); recorded != "unknown" {
			connectorVersion = recorded
		}
	}
	connectorLoaded, configTestOK := connectorStatus(ctx, webServer, cfg.WebServerBinary)
	return model.Inventory{
		Hostname: hostname, OSID: osRelease["ID"], OSVersion: osRelease["VERSION_ID"], Architecture: runtime.GOARCH,
		WebServer: webServer, WebServerVersion: webVersion, WebServerBuild: webBuild, IntegrationMode: cfg.IntegrationMode,
		InstallationMode: cfg.InstallationMode, AgentVersion: version.Version, ModuleVersion: moduleVersion, CRSVersion: appliedCRSVersion(cfg.PolicyPath),
		ConnectorVersion: connectorVersion, ConnectorLoaded: connectorLoaded, ConfigTestOK: configTestOK,
		PolicyFormats: []string{"conf-v1", policybundle.Format, policybundle.FormatV3},
	}, nil
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

func connectorStatus(parent context.Context, webServer, configuredBinary string) (bool, bool) {
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
	if webServer == "apache" {
		if err := exec.CommandContext(ctx, binary, "configtest").Run(); err != nil {
			return false, false
		}
		output, err := exec.CommandContext(ctx, binary, "-M").CombinedOutput()
		return err == nil && strings.Contains(string(output), "security2_module"), true
	}
	if webServer == "nginx" {
		if err := exec.CommandContext(ctx, binary, "-t").Run(); err != nil {
			return false, false
		}
		output, err := exec.CommandContext(ctx, binary, "-T").CombinedOutput()
		loaded := err == nil && (strings.Contains(string(output), "modsecurity on;") || strings.Contains(string(output), "modsecurity_rules_file"))
		return loaded, true
	}
	return false, false
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
