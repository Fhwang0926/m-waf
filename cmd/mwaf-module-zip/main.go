package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

type moduleManifest struct {
	SchemaVersion  int    `json:"schema_version"`
	WebServer      string `json:"web_server"`
	Version        string `json:"version"`
	WebServerBuild string `json:"web_server_build_hash"`
	RuntimeABI     string `json:"runtime_abi"`
}

func main() {
	input := flag.String("input", "", "directory containing module/ and integration/mwaf.conf")
	output := flag.String("output", "", "output ZIP path")
	metadataOutput := flag.String("metadata-output", "", "output package metadata JSON path")
	id := flag.String("id", "", "unique package id")
	name := flag.String("name", "mwaf-custom-module", "package display name")
	version := flag.String("version", "", "module release version")
	osID := flag.String("os-id", "", "target OS id")
	osVersion := flag.String("os-version", "", "target OS version")
	webServer := flag.String("webserver", "", "apache or nginx")
	webServerBuild := flag.String("webserver-build", "", "exact Agent inventory build hash")
	runtimeABI := flag.String("runtime-abi", "", "connector runtime ABI")
	flag.Parse()
	artifact := model.PackageArtifact{
		ID: *id, Kind: "module", Name: *name, Version: *version, OSID: *osID, OSVersion: *osVersion, Architecture: "amd64",
		WebServer: *webServer, WebServerBuild: *webServerBuild, IntegrationMode: model.IntegrationModeExternal, RuntimeABI: *runtimeABI,
		PolicyDelivery: "bundle", Path: filepath.Base(*output), PackageFormat: model.PackageFormatZIP, InstallRoot: "/opt/m-waf",
	}
	if err := build(*input, *output, *metadataOutput, artifact); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(input, output, metadataOutput string, artifact model.PackageArtifact) error {
	if input == "" || output == "" || metadataOutput == "" || artifact.ID == "" || artifact.Version == "" || artifact.OSID == "" || artifact.OSVersion == "" || artifact.WebServerBuild == "" || artifact.RuntimeABI == "" {
		return errors.New("input, output, metadata-output, id, version, OS, build hash, and runtime ABI are required")
	}
	if artifact.WebServer != "apache" && artifact.WebServer != "nginx" {
		return errors.New("webserver must be apache or nginx")
	}
	input, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	var files []string
	err = filepath.WalkDir(input, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == input {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed in custom module input: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(input, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "mwaf-module.json" || strings.HasPrefix(relative, "../") {
			return fmt.Errorf("reserved or unsafe input path: %s", relative)
		}
		files = append(files, relative)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	moduleFound, integrationFound := false, false
	for _, name := range files {
		moduleFound = moduleFound || strings.HasPrefix(name, "module/")
		integrationFound = integrationFound || name == "integration/mwaf.conf"
	}
	if !moduleFound || !integrationFound {
		return errors.New("input requires at least one module/ file and integration/mwaf.conf")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	destination, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(destination)
	manifestRaw, err := json.MarshalIndent(moduleManifest{SchemaVersion: 1, WebServer: artifact.WebServer, Version: artifact.Version, WebServerBuild: artifact.WebServerBuild, RuntimeABI: artifact.RuntimeABI}, "", "  ")
	if err == nil {
		err = writeZIPFile(archive, "mwaf-module.json", append(manifestRaw, '\n'), 0o640)
	}
	for _, name := range files {
		if err != nil {
			break
		}
		path := filepath.Join(input, filepath.FromSlash(name))
		info, statErr := os.Stat(path)
		if statErr != nil {
			err = statErr
			break
		}
		source, openErr := os.Open(path)
		if openErr != nil {
			err = openErr
			break
		}
		err = writeZIPReader(archive, name, source, info.Mode().Perm())
		closeErr := source.Close()
		if err == nil {
			err = closeErr
		}
	}
	closeArchiveErr := archive.Close()
	closeFileErr := destination.Close()
	if err == nil {
		err = closeArchiveErr
	}
	if err == nil {
		err = closeFileErr
	}
	if err != nil {
		_ = os.Remove(output)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(metadataOutput), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metadataOutput, append(raw, '\n'), 0o644)
}

func writeZIPFile(archive *zip.Writer, name string, raw []byte, mode os.FileMode) error {
	return writeZIPReader(archive, name, strings.NewReader(string(raw)), mode)
}

func writeZIPReader(archive *zip.Writer, name string, source io.Reader, mode os.FileMode) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
	header.SetMode(mode & 0o755)
	destination, err := archive.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, source)
	return err
}
