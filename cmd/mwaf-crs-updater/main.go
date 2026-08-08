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

var errUntrustedTag = errors.New("untrusted CRS release tag")

const (
	defaultRepository = "coreruleset/coreruleset"
	maxArchiveBytes   = 256 << 20
)

type sourceLock struct {
	Channel     string
	Line        string
	Repository  string
	Version     string
	Commit      string
	TagObject   string
	TagVerified bool
	Archive     string
	SHA256      string
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

func main() {
	lockPath := flag.String("lock", "packaging/sources.lock.yaml", "CRS source lock path")
	channel := flag.String("channel", "stable", "release channel: stable or lts")
	write := flag.Bool("write", false, "write an available verified source candidate to the lock")
	field := flag.String("field", "", "print one locked field without accessing the network")
	flag.Parse()

	locked, raw, err := readSourceLock(*lockPath, *channel)
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
	if *channel != "stable" && *channel != "lts" {
		fatal(errors.New("channel must be stable or lts"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 90 * time.Second}
	latest, commit, tagObject, err := latestSignedRelease(ctx, client, locked.Repository, *channel, locked.Line)
	if err != nil {
		fatal(err)
	}
	if compareVersions(latest.TagName, locked.Version) <= 0 {
		fmt.Printf("CRS %s is current at %s\n", *channel, locked.Version)
		return
	}

	archive := "https://github.com/" + locked.Repository + "/archive/" + commit + ".tar.gz"
	digest, err := archiveSHA256(ctx, client, archive)
	if err != nil {
		fatal(err)
	}
	next := sourceLock{Channel: locked.Channel, Line: locked.Line, Repository: locked.Repository, Version: latest.TagName, Commit: commit, TagObject: tagObject, TagVerified: true, Archive: archive, SHA256: digest}
	if !*write {
		fmt.Printf("CRS update available: %s -> %s (%s)\n", locked.Version, next.Version, next.Commit)
		return
	}
	updated, err := rewriteSourceLock(raw, next)
	if err != nil {
		fatal(err)
	}
	if err := atomicWrite(*lockPath, updated, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("updated CRS %s from %s to %s\n", *channel, locked.Version, next.Version)
}

func latestSignedRelease(ctx context.Context, client *http.Client, repository, channel, lockedLine string) (release, string, string, error) {
	var releases []release
	if err := getJSON(ctx, client, "https://api.github.com/repos/"+repository+"/releases?per_page=50", &releases); err != nil {
		return release{}, "", "", err
	}
	var candidates []release
	for _, item := range releases {
		if item.Draft || item.Prerelease || !strings.HasPrefix(item.TagName, "v4.") {
			continue
		}
		if channel == "lts" && !strings.HasPrefix(strings.TrimPrefix(item.TagName, "v"), strings.TrimPrefix(lockedLine, "v")+".") {
			continue
		}
		candidates = append(candidates, item)
	}
	if len(candidates) == 0 {
		return release{}, "", "", fmt.Errorf("no %s CRS v4 release found", channel)
	}
	sort.Slice(candidates, func(i, j int) bool { return compareVersions(candidates[i].TagName, candidates[j].TagName) > 0 })
	var verificationErrors []error
	for _, candidate := range candidates {
		commit, tagObject, err := verifiedTagCommit(ctx, client, repository, candidate.TagName)
		if err == nil {
			return candidate, commit, tagObject, nil
		}
		if !errors.Is(err, errUntrustedTag) {
			return release{}, "", "", err
		}
		verificationErrors = append(verificationErrors, fmt.Errorf("%s: %w", candidate.TagName, err))
	}
	return release{}, "", "", fmt.Errorf("no signed %s CRS v4 release found: %w", channel, errors.Join(verificationErrors...))
}

func verifiedTagCommit(ctx context.Context, client *http.Client, repository, tagName string) (string, string, error) {
	var ref gitReference
	endpoint := "https://api.github.com/repos/" + repository + "/git/ref/tags/" + url.PathEscape(tagName)
	if err := getJSON(ctx, client, endpoint, &ref); err != nil {
		return "", "", err
	}
	if ref.Object.Type != "tag" {
		return "", "", fmt.Errorf("%w: release tag is not annotated", errUntrustedTag)
	}
	var tag gitTag
	if err := getJSON(ctx, client, "https://api.github.com/repos/"+repository+"/git/tags/"+ref.Object.SHA, &tag); err != nil {
		return "", "", err
	}
	if !tag.Verification.Verified {
		return "", "", fmt.Errorf("%w: signature is not verified: %s", errUntrustedTag, tag.Verification.Reason)
	}
	if tag.Object.Type != "commit" || tag.Object.SHA == "" {
		return "", "", fmt.Errorf("%w: tag does not resolve to a commit", errUntrustedTag)
	}
	return tag.Object.SHA, ref.Object.SHA, nil
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

func readSourceLock(path, channel string) (sourceLock, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sourceLock{}, nil, err
	}
	lock := sourceLock{Channel: channel}
	inCRS := false
	inSelected := false
	legacy := false
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
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			key, value, ok := strings.Cut(strings.TrimPrefix(trimmed, "- "), ":")
			inSelected = ok && key == "channel" && unquoteYAML(value) == channel
			continue
		}
		if !strings.Contains(string(raw), "  - channel:") {
			legacy = true
			inSelected = channel == "stable"
		}
		if !inSelected {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = unquoteYAML(value)
		switch key {
		case "line":
			lock.Line = value
		case "repository":
			lock.Repository = strings.TrimPrefix(value, "https://github.com/")
		case "version":
			lock.Version = value
		case "commit":
			lock.Commit = value
		case "tag_object_sha":
			lock.TagObject = value
		case "tag_signature_verified":
			lock.TagVerified = value == "true"
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
	if channel == "lts" && lock.Line == "" {
		return sourceLock{}, nil, errors.New("CRS LTS source lock requires a line")
	}
	if lock.Version == "" || lock.Commit == "" || lock.Archive == "" || len(lock.SHA256) != 64 || !legacy && (len(lock.TagObject) != 40 || !lock.TagVerified) {
		return sourceLock{}, nil, errors.New("CRS source lock is incomplete")
	}
	return lock, raw, nil
}

func unquoteYAML(value string) string {
	return strings.Trim(strings.TrimSpace(value), "'\"")
}

func rewriteSourceLock(raw []byte, lock sourceLock) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	inCRS := false
	inSelected := false
	seen := make(map[string]bool)
	values := map[string]string{
		"repository":             "https://github.com/" + lock.Repository,
		"version":                lock.Version,
		"commit":                 lock.Commit,
		"tag_object_sha":         lock.TagObject,
		"tag_signature_verified": strconv.FormatBool(lock.TagVerified),
		"archive":                lock.Archive,
		"sha256":                 lock.SHA256,
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
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			key, value, ok := strings.Cut(strings.TrimPrefix(trimmed, "- "), ":")
			inSelected = ok && key == "channel" && unquoteYAML(value) == lock.Channel
			continue
		}
		if !inSelected {
			continue
		}
		key, _, ok := strings.Cut(trimmed, ":")
		if value, replace := values[key]; ok && replace {
			lines[index] = "    " + key + ": " + value
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

func lockField(lock sourceLock, field string) (string, error) {
	switch field {
	case "channel":
		return lock.Channel, nil
	case "line":
		return lock.Line, nil
	case "repository":
		return lock.Repository, nil
	case "version":
		return lock.Version, nil
	case "version-number":
		return strings.TrimPrefix(lock.Version, "v"), nil
	case "commit":
		return lock.Commit, nil
	case "tag-object-sha":
		return lock.TagObject, nil
	case "tag-signature-verified":
		return strconv.FormatBool(lock.TagVerified), nil
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
