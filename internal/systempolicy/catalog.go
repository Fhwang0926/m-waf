package systempolicy

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed catalog.json templates/*.json
var policyFiles embed.FS

const DefaultTemplateKey = "crs-baseline"

const (
	StatusPublished  = "PUBLISHED"
	StatusDeprecated = "DEPRECATED"
	StatusWithdrawn  = "WITHDRAWN"
)

type Defaults struct {
	Mode          string `json:"mode"`
	ParanoiaLevel int    `json:"paranoia_level"`
	InboundScore  int    `json:"inbound_anomaly_score"`
	RequestBody   bool   `json:"request_body_access"`
}

type Template struct {
	SchemaVersion  int      `json:"schema_version"`
	Key            string   `json:"key"`
	Version        string   `json:"version"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	CRSTrack       string   `json:"crs_track"`
	CRSVersion     string   `json:"crs_version"`
	Defaults       Defaults `json:"defaults"`
	MigrationNotes []string `json:"migration_notes,omitempty"`
	Status         string   `json:"-"`
	Digest         string   `json:"-"`
}

func (t Template) Reference() string { return t.Key + "@" + t.Version }

type lifecycleCatalog struct {
	DefaultKey string            `json:"default_key"`
	Policies   []policyLifecycle `json:"policies"`
}

type policyLifecycle struct {
	Key            string            `json:"key"`
	CurrentVersion string            `json:"current_version"`
	Versions       map[string]string `json:"versions"`
}

type Catalog struct {
	items      []Template
	byKey      map[string]Template
	byRefs     map[string]Template
	defaultKey string
}

func Load() (*Catalog, error) {
	lifecycleRaw, err := policyFiles.ReadFile("catalog.json")
	if err != nil {
		return nil, fmt.Errorf("read system policy lifecycle: %w", err)
	}
	var lifecycle lifecycleCatalog
	if err := json.Unmarshal(lifecycleRaw, &lifecycle); err != nil {
		return nil, fmt.Errorf("decode system policy lifecycle: %w", err)
	}
	if lifecycle.DefaultKey == "" {
		return nil, errors.New("system policy default_key is required")
	}
	statuses := make(map[string]string)
	currentRefs := make(map[string]string)
	for _, policy := range lifecycle.Policies {
		if policy.Key == "" || policy.CurrentVersion == "" || len(policy.Versions) == 0 {
			return nil, errors.New("system policy lifecycle requires key, current_version and versions")
		}
		for version, status := range policy.Versions {
			if !validStatus(status) {
				return nil, fmt.Errorf("system policy %s@%s has invalid status %q", policy.Key, version, status)
			}
			statuses[policy.Key+"@"+version] = status
		}
		currentRef := policy.Key + "@" + policy.CurrentVersion
		if statuses[currentRef] != StatusPublished {
			return nil, fmt.Errorf("current system policy %s must be published", currentRef)
		}
		currentRefs[policy.Key] = currentRef
	}

	entries, err := fs.ReadDir(policyFiles, "templates")
	if err != nil {
		return nil, fmt.Errorf("read system policy templates: %w", err)
	}
	catalog := &Catalog{byKey: make(map[string]Template), byRefs: make(map[string]Template), defaultKey: lifecycle.DefaultKey}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := policyFiles.ReadFile("templates/" + entry.Name())
		if err != nil {
			return nil, err
		}
		var item Template
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("decode system policy template %s: %w", entry.Name(), err)
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("system policy template %s: %w", entry.Name(), err)
		}
		status, exists := statuses[item.Reference()]
		if !exists {
			return nil, fmt.Errorf("system policy template %s is missing lifecycle metadata", item.Reference())
		}
		digest := sha256.Sum256(raw)
		item.Status = status
		item.Digest = hex.EncodeToString(digest[:])
		if _, exists := catalog.byRefs[item.Reference()]; exists {
			return nil, fmt.Errorf("duplicate system policy template %q", item.Reference())
		}
		catalog.items = append(catalog.items, item)
		catalog.byRefs[item.Reference()] = item
		if currentRefs[item.Key] == item.Reference() {
			catalog.byKey[item.Key] = item
		}
	}
	if len(catalog.items) != len(statuses) {
		return nil, errors.New("system policy lifecycle and template versions do not match")
	}
	if _, ok := catalog.byKey[catalog.defaultKey]; !ok {
		return nil, fmt.Errorf("default system policy %q is missing", catalog.defaultKey)
	}
	if catalog.byKey[catalog.defaultKey].Defaults.Mode != "DetectionOnly" {
		return nil, errors.New("default system policy must start in DetectionOnly mode")
	}
	sort.Slice(catalog.items, func(i, j int) bool {
		if catalog.items[i].Key == catalog.items[j].Key {
			return compareVersion(catalog.items[i].Version, catalog.items[j].Version) > 0
		}
		return catalog.items[i].Key < catalog.items[j].Key
	})
	return catalog, nil
}

func (c *Catalog) Latest(key string) (Template, bool) {
	item, ok := c.byKey[key]
	return item, ok
}

func (c *Catalog) Version(key, version string) (Template, bool) {
	item, ok := c.byRefs[key+"@"+version]
	return item, ok
}

func (c *Catalog) Default() Template { return c.byKey[c.defaultKey] }

func (c *Catalog) List() []Template {
	return append([]Template(nil), c.items...)
}

func (c *Catalog) ListLatest() []Template {
	items := make([]Template, 0, len(c.byKey))
	for _, item := range c.byKey {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items
}

func (t Template) Validate() error {
	if t.SchemaVersion < 1 || t.Key == "" || t.Version == "" || t.Name == "" || t.CRSVersion == "" {
		return errors.New("schema_version, key, version, name and crs_version are required")
	}
	if t.CRSTrack != "stable" && t.CRSTrack != "lts" {
		return errors.New("crs_track must be stable or lts")
	}
	if t.Defaults.Mode != "DetectionOnly" && t.Defaults.Mode != "On" {
		return errors.New("default mode must be DetectionOnly or On")
	}
	if t.Defaults.ParanoiaLevel < 1 || t.Defaults.ParanoiaLevel > 4 {
		return errors.New("default paranoia level must be 1..4")
	}
	if t.Defaults.InboundScore < 1 || t.Defaults.InboundScore > 100 {
		return errors.New("default inbound score must be 1..100")
	}
	return nil
}

func validStatus(status string) bool {
	return status == StatusPublished || status == StatusDeprecated || status == StatusWithdrawn
}

func compareVersion(left, right string) int {
	for i := 0; i < 3; i++ {
		var l, r int
		_, _ = fmt.Sscanf(versionPart(left, i), "%d", &l)
		_, _ = fmt.Sscanf(versionPart(right, i), "%d", &r)
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	return strings.Compare(left, right)
}

func versionPart(version string, index int) string {
	parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 4)
	if index >= len(parts) {
		return "0"
	}
	return parts[index]
}
