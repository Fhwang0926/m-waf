package crssource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
)

const (
	Repository      = "coreruleset/coreruleset"
	RepositoryURL   = "https://github.com/coreruleset/coreruleset"
	PolicyFormatV3  = "policy-bundle-v3"
	maxArchiveBytes = 256 << 20
)

var errUntrustedTag = errors.New("untrusted CRS release tag")

type Client struct {
	httpClient *http.Client
	token      string
}

type Fetched struct {
	Source  model.PolicySourceArtifact
	Index   crsindex.Index
	Archive []byte
}

// RejectedSourceError preserves immutable release identity when the downloaded
// official source cannot be indexed, allowing Manager to record REJECTED.
type RejectedSourceError struct {
	Source model.PolicySourceArtifact
	Err    error
}

func (e *RejectedSourceError) Error() string { return e.Err.Error() }

func (e *RejectedSourceError) Unwrap() error { return e.Err }

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

func NewClient(token string) *Client {
	client := &http.Client{Timeout: 90 * time.Second}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many CRS download redirects")
		}
		host := strings.ToLower(request.URL.Hostname())
		if host != "github.com" && host != "codeload.github.com" {
			return fmt.Errorf("CRS download redirected to untrusted host %q", host)
		}
		return nil
	}
	return &Client{httpClient: client, token: strings.TrimSpace(token)}
}

func (c *Client) FetchLatest(ctx context.Context) (Fetched, error) {
	return c.FetchLatestChannel(ctx, "stable", "")
}

// FetchLatestChannel resolves the highest signed stable tag, or the highest
// patch release inside the CI-selected LTS major/minor line. It never chooses a
// new LTS line on its own.
func (c *Client) FetchLatestChannel(ctx context.Context, channel, ltsLine string) (Fetched, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	if channel != "stable" && channel != "lts" {
		return Fetched{}, errors.New("CRS channel must be stable or lts")
	}
	if channel == "lts" && !validLTSLine(ltsLine) {
		return Fetched{}, errors.New("CRS LTS channel requires a major.minor line")
	}
	tag, commit, tagObjectSHA, err := c.latestSignedTag(ctx, channel, ltsLine)
	if err != nil {
		return Fetched{}, err
	}
	// Fetch by the verified commit rather than by the mutable tag name so the
	// archive cannot change between tag verification and download.
	archiveURL := "https://github.com/" + Repository + "/archive/" + url.PathEscape(commit) + ".tar.gz"
	archive, err := c.download(ctx, archiveURL)
	if err != nil {
		return Fetched{}, err
	}
	archiveDigest := sha256.Sum256(archive)
	archiveSHA := hex.EncodeToString(archiveDigest[:])
	version := strings.TrimPrefix(tag, "v")
	shortCommit := commit
	if len(shortCommit) > 12 {
		shortCommit = shortCommit[:12]
	}
	source := model.PolicySourceArtifact{
		ID: "owasp-crs-" + channel + "-" + version + "-" + shortCommit, Provider: "github", Repository: RepositoryURL, Channel: channel,
		Version: version, Tag: tag, Commit: commit, TagObjectSHA: tagObjectSHA, TagSignatureVerified: true,
		ArchivePath: "archive.tar.gz", ArchiveSize: int64(len(archive)), ArchiveSHA256: archiveSHA, IndexPath: "index.json", ArtifactFormat: PolicyFormatV3,
	}
	index, err := crsindex.BuildFromArchive(bytes.NewReader(archive), crsindex.Source{
		Provider: "github", Repository: RepositoryURL, Channel: channel, Version: version, Tag: tag, Commit: commit, ArchiveSHA256: archiveSHA,
	})
	if err != nil {
		return Fetched{}, &RejectedSourceError{Source: source, Err: err}
	}
	if _, err := crsindex.PolicyFilesFromArchive(bytes.NewReader(archive)); err != nil {
		return Fetched{}, &RejectedSourceError{Source: source, Err: err}
	}
	indexRaw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return Fetched{}, err
	}
	indexRaw = append(indexRaw, '\n')
	indexDigest := sha256.Sum256(indexRaw)
	source.IndexSize = int64(len(indexRaw))
	source.IndexSHA256 = hex.EncodeToString(indexDigest[:])
	return Fetched{Source: source, Index: index, Archive: archive}, nil
}

func (c *Client) latestTag(ctx context.Context, channel, ltsLine string) (string, error) {
	tags, err := c.candidateTags(ctx, channel, ltsLine)
	if err != nil {
		return "", err
	}
	return tags[0], nil
}

func (c *Client) latestSignedTag(ctx context.Context, channel, ltsLine string) (string, string, string, error) {
	tags, err := c.candidateTags(ctx, channel, ltsLine)
	if err != nil {
		return "", "", "", err
	}
	var verificationErrors []error
	for _, tag := range tags {
		commit, tagObjectSHA, err := c.verifiedTagCommit(ctx, tag)
		if err == nil {
			return tag, commit, tagObjectSHA, nil
		}
		if !errors.Is(err, errUntrustedTag) {
			return "", "", "", fmt.Errorf("verify CRS release %s: %w", tag, err)
		}
		verificationErrors = append(verificationErrors, fmt.Errorf("%s: %w", tag, err))
	}
	return "", "", "", fmt.Errorf("no signed %s OWASP CRS release found: %w", channel, errors.Join(verificationErrors...))
}

func (c *Client) candidateTags(ctx context.Context, channel, ltsLine string) ([]string, error) {
	var releases []release
	if err := c.getJSON(ctx, "https://api.github.com/repos/"+Repository+"/releases?per_page=50", &releases); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(releases))
	for _, item := range releases {
		matchesLine := channel == "stable" || strings.HasPrefix(strings.TrimPrefix(item.TagName, "v"), strings.TrimPrefix(ltsLine, "v")+".")
		if !item.Draft && !item.Prerelease && strings.HasPrefix(item.TagName, "v4.") && matchesLine {
			tags = append(tags, item.TagName)
		}
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("no %s OWASP CRS v4 release found", channel)
	}
	sort.Slice(tags, func(i, j int) bool { return compareVersion(tags[i], tags[j]) > 0 })
	return tags, nil
}

func validLTSLine(value string) bool {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return parts[0] == "4"
}

func (c *Client) verifiedTagCommit(ctx context.Context, tagName string) (string, string, error) {
	var reference gitReference
	if err := c.getJSON(ctx, "https://api.github.com/repos/"+Repository+"/git/ref/tags/"+url.PathEscape(tagName), &reference); err != nil {
		return "", "", err
	}
	if reference.Object.Type != "tag" {
		return "", "", fmt.Errorf("%w: release tag is not annotated", errUntrustedTag)
	}
	var tag gitTag
	if err := c.getJSON(ctx, "https://api.github.com/repos/"+Repository+"/git/tags/"+reference.Object.SHA, &tag); err != nil {
		return "", "", err
	}
	if !tag.Verification.Verified {
		return "", "", fmt.Errorf("%w: signature is not verified: %s", errUntrustedTag, tag.Verification.Reason)
	}
	if tag.Object.Type != "commit" || tag.Object.SHA == "" {
		return "", "", fmt.Errorf("%w: tag does not resolve to a commit", errUntrustedTag)
	}
	return tag.Object.SHA, reference.Object.SHA, nil
}

func (c *Client) getJSON(ctx context.Context, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "m-waf-manager")
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(target)
}

func (c *Client) download(ctx context.Context, endpoint string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "m-waf-manager")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download CRS archive: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxArchiveBytes {
		return nil, errors.New("CRS archive exceeds 256 MiB")
	}
	return raw, nil
}

func compareVersion(left, right string) int {
	parse := func(value string) [3]int {
		var result [3]int
		parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
		for index := range result {
			if index < len(parts) {
				result[index], _ = strconv.Atoi(parts[index])
			}
		}
		return result
	}
	l, r := parse(left), parse(right)
	for index := range l {
		if l[index] < r[index] {
			return -1
		}
		if l[index] > r[index] {
			return 1
		}
	}
	return 0
}
