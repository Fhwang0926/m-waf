package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRepository = "coreruleset/coreruleset"
	maxArchiveBytes   = 256 << 20
)

type sourceLock struct {
	Repository string
	Version    string
	Commit     string
	Archive    string
	SHA256     string
}

type release struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

type gitReference struct {
	Object gitObject `json:"object"`
}

type gitTag struct {
	Object       gitObject `json:"object"`
	Verification struct {
		Verified bool   `json:"verified"`
		Reason   string `json:"reason"`
	} `json:"verification"`
}

type templateUpdate struct {
	Key             string
	PreviousVersion string
	Version         string
}

type lifecycleCatalog struct {
	DefaultKey string            `json:"default_key"`
	Policies   []policyLifecycle `json:"policies"`
}

type policyLifecycle struct {
	Key            string            `json:"key"`
	CurrentVersion string            `json:"current_version"`
	Versions       map[string]string `json:"versions"`
}

func main() {
	lockPath := flag.String("lock", "packaging/sources.lock.yaml", "CRS source lock path")
	templateDir := flag.String("templates", "internal/systempolicy/templates", "system policy template directory")
	catalogPath := flag.String("catalog", "internal/systempolicy/catalog.json", "system policy lifecycle catalog path")
	channel := flag.String("channel", "stable", "release channel: stable")
	write := flag.Bool("write", false, "write an available update to the lock and matching templates")
	field := flag.String("field", "", "print one locked field without accessing the network")
	flag.Parse()

	locked, raw, err := readSourceLock(*lockPath)
	if err != nil {
		fatal(err)
	}
	if *field != "" {
		value, err := lockField(locked, *field)
		if err != nil {
			fatal(err)
		}
		fmt.Println(value)
		return
	}
	if *channel != "stable" {
		fatal(errors.New("channel must be stable"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 90 * time.Second}
	latest, err := latestRelease(ctx, client, locked.Repository, *channel)
	if err != nil {
		fatal(err)
	}
	if compareVersions(latest.TagName, locked.Version) <= 0 {
		fmt.Printf("CRS %s is current at %s\n", *channel, locked.Version)
		return
	}

	commit, err := verifiedTagCommit(ctx, client, locked.Repository, latest.TagName)
	if err != nil {
		fatal(err)
	}
	archive := "https://github.com/" + locked.Repository + "/archive/refs/tags/" + latest.TagName + ".tar.gz"
	digest, err := archiveSHA256(ctx, client, archive)
	if err != nil {
		fatal(err)
	}
	next := sourceLock{Repository: locked.Repository, Version: latest.TagName, Commit: commit, Archive: archive, SHA256: digest}
	if !*write {
		fmt.Printf("CRS update available: %s -> %s (%s)\n", locked.Version, next.Version, next.Commit)
		return
	}
	updated, err := rewriteSourceLock(raw, next)
	if err != nil {
		fatal(err)
	}
	lifecycle, err := readLifecycleCatalog(*catalogPath)
	if err != nil {
		fatal(err)
	}
	templateUpdates, err := updateTemplates(*templateDir, *channel, strings.TrimPrefix(next.Version, "v"), lifecycle)
	if err != nil {
		fatal(err)
	}
	if err := updateLifecycleCatalog(*catalogPath, templateUpdates); err != nil {
		fatal(err)
	}
	if err := atomicWrite(*lockPath, updated, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("updated CRS %s from %s to %s\n", *channel, locked.Version, next.Version)
}

func latestRelease(ctx context.Context, client *http.Client, repository, channel string) (release, error) {
	var releases []release
	if err := getJSON(ctx, client, "https://api.github.com/repos/"+repository+"/releases?per_page=50", &releases); err != nil {
		return release{}, err
	}
	var selected release
	for _, item := range releases {
		if item.Draft || item.Prerelease || !strings.HasPrefix(item.TagName, "v4.") {
			continue
		}
		if selected.TagName == "" || compareVersions(item.TagName, selected.TagName) > 0 {
			selected = item
		}
	}
	if selected.TagName == "" {
		return release{}, fmt.Errorf("no %s CRS v4 release found", channel)
	}
	return selected, nil
}

func verifiedTagCommit(ctx context.Context, client *http.Client, repository, tagName string) (string, error) {
	var ref gitReference
	endpoint := "https://api.github.com/repos/" + repository + "/git/ref/tags/" + url.PathEscape(tagName)
	if err := getJSON(ctx, client, endpoint, &ref); err != nil {
		return "", err
	}
	if ref.Object.Type != "tag" {
		return "", errors.New("CRS release tag is not an annotated signed tag")
	}
	var tag gitTag
	if err := getJSON(ctx, client, "https://api.github.com/repos/"+repository+"/git/tags/"+ref.Object.SHA, &tag); err != nil {
		return "", err
	}
	if !tag.Verification.Verified {
		return "", fmt.Errorf("CRS release tag signature is not verified: %s", tag.Verification.Reason)
	}
	if tag.Object.Type != "commit" || tag.Object.SHA == "" {
		return "", errors.New("CRS release tag does not resolve to a commit")
	}
	return tag.Object.SHA, nil
}

func archiveSHA256(ctx context.Context, client *http.Client, archive string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archive, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download CRS archive: HTTP %d", resp.StatusCode)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxArchiveBytes {
		return "", errors.New("CRS archive exceeds 256 MiB")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "m-waf-crs-updater")
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API %s: HTTP %d", endpoint, resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	return nil
}

func readSourceLock(path string) (sourceLock, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sourceLock{}, nil, err
	}
	lock := sourceLock{}
	inCRS := false
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "crs:" {
			inCRS = true
			continue
		}
		if inCRS && line != "" && line[0] != ' ' {
			break
		}
		if !inCRS {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "repository":
			lock.Repository = strings.TrimPrefix(value, "https://github.com/")
		case "version":
			lock.Version = value
		case "commit":
			lock.Commit = value
		case "archive":
			lock.Archive = value
		case "sha256":
			lock.SHA256 = value
		}
	}
	if err := scanner.Err(); err != nil {
		return sourceLock{}, nil, err
	}
	if lock.Repository == "" {
		lock.Repository = defaultRepository
	}
	if lock.Version == "" || lock.Commit == "" || lock.Archive == "" || len(lock.SHA256) != 64 {
		return sourceLock{}, nil, errors.New("CRS source lock is incomplete")
	}
	return lock, raw, nil
}

func rewriteSourceLock(raw []byte, lock sourceLock) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	inCRS := false
	seen := make(map[string]bool)
	values := map[string]string{
		"repository": "https://github.com/" + lock.Repository,
		"version":    lock.Version,
		"commit":     lock.Commit,
		"archive":    lock.Archive,
		"sha256":     lock.SHA256,
	}
	for index, line := range lines {
		if line == "crs:" {
			inCRS = true
			continue
		}
		if inCRS && line != "" && line[0] != ' ' {
			break
		}
		if !inCRS {
			continue
		}
		key, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if value, replace := values[key]; ok && replace {
			lines[index] = "  " + key + ": " + value
			seen[key] = true
		}
	}
	for key := range values {
		if !seen[key] {
			return nil, fmt.Errorf("CRS source lock key %q is missing", key)
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func updateTemplates(directory, channel, crsVersion string, lifecycle lifecycleCatalog) ([]templateUpdate, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		item    map[string]any
		version string
	}
	currentVersions := make(map[string]string, len(lifecycle.Policies))
	for _, policy := range lifecycle.Policies {
		if policy.Key == "" || policy.CurrentVersion == "" || policy.Versions[policy.CurrentVersion] != "PUBLISHED" {
			return nil, errors.New("system policy lifecycle current version must be published")
		}
		currentVersions[policy.Key] = policy.CurrentVersion
	}
	currentByKey := make(map[string]candidate)
	updates := make([]templateUpdate, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if item["crs_track"] != channel {
			continue
		}
		key, _ := item["key"].(string)
		version, _ := item["version"].(string)
		if key == "" || version == "" {
			return nil, fmt.Errorf("template %s is missing key or version", path)
		}
		if currentVersions[key] == version {
			currentByKey[key] = candidate{item: item, version: version}
		}
	}
	keys := make([]string, 0, len(currentByKey))
	for key := range currentByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		current := currentByKey[key]
		if current.item["crs_version"] == crsVersion {
			continue
		}
		nextVersion := bumpPatch(current.version)
		current.item["version"] = nextVersion
		current.item["crs_version"] = crsVersion
		formatted, err := json.MarshalIndent(current.item, "", "  ")
		if err != nil {
			return nil, err
		}
		path := filepath.Join(directory, key+"."+nextVersion+".json")
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("template version already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := atomicWrite(path, append(formatted, '\n'), 0o644); err != nil {
			return nil, err
		}
		updates = append(updates, templateUpdate{Key: key, PreviousVersion: current.version, Version: nextVersion})
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("no %s system policy template was updated", channel)
	}
	return updates, nil
}

func readLifecycleCatalog(path string) (lifecycleCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return lifecycleCatalog{}, err
	}
	var catalog lifecycleCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return lifecycleCatalog{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return catalog, nil
}

func updateLifecycleCatalog(path string, updates []templateUpdate) error {
	catalog, err := readLifecycleCatalog(path)
	if err != nil {
		return err
	}
	for _, update := range updates {
		found := false
		for index := range catalog.Policies {
			policy := &catalog.Policies[index]
			if policy.Key != update.Key {
				continue
			}
			found = true
			if policy.CurrentVersion != update.PreviousVersion || policy.Versions[update.PreviousVersion] != "PUBLISHED" {
				return fmt.Errorf("system policy %s current lifecycle does not match template %s", update.Key, update.PreviousVersion)
			}
			if _, exists := policy.Versions[update.Version]; exists {
				return fmt.Errorf("system policy lifecycle already contains %s@%s", update.Key, update.Version)
			}
			policy.Versions[update.PreviousVersion] = "DEPRECATED"
			policy.Versions[update.Version] = "PUBLISHED"
			policy.CurrentVersion = update.Version
			break
		}
		if !found {
			return fmt.Errorf("system policy lifecycle is missing key %s", update.Key)
		}
	}
	formatted, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(formatted, '\n'), 0o644)
}

func bumpPatch(version string) string {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return version + ".1"
	}
	parts[2] = strconv.Itoa(patch + 1)
	return strings.Join(parts[:3], ".")
}

func lockField(lock sourceLock, field string) (string, error) {
	switch field {
	case "repository":
		return lock.Repository, nil
	case "version":
		return lock.Version, nil
	case "version-number":
		return strings.TrimPrefix(lock.Version, "v"), nil
	case "commit":
		return lock.Commit, nil
	case "archive":
		return lock.Archive, nil
	case "sha256":
		return lock.SHA256, nil
	default:
		return "", fmt.Errorf("unknown lock field %q", field)
	}
}

func compareVersions(left, right string) int {
	l := numericVersion(left)
	r := numericVersion(right)
	for i := 0; i < 3; i++ {
		if l[i] < r[i] {
			return -1
		}
		if l[i] > r[i] {
			return 1
		}
	}
	return 0
}

func numericVersion(version string) [3]int {
	var result [3]int
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	for i := 0; i < len(result) && i < len(parts); i++ {
		result[i], _ = strconv.Atoi(parts[i])
	}
	return result
}

func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".crs-update-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
