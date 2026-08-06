package systempolicy

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed templates/*.json
var templateFiles embed.FS

const DefaultTemplateKey = "crs-baseline"

type Defaults struct {
	Mode          string `json:"mode"`
	ParanoiaLevel int    `json:"paranoia_level"`
	InboundScore  int    `json:"inbound_anomaly_score"`
	RequestBody   bool   `json:"request_body_access"`
}

type Template struct {
	SchemaVersion int      `json:"schema_version"`
	Key           string   `json:"key"`
	Version       string   `json:"version"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	CRSTrack      string   `json:"crs_track"`
	CRSVersion    string   `json:"crs_version"`
	Defaults      Defaults `json:"defaults"`
}

func (t Template) Reference() string { return t.Key + "@" + t.Version }

type Catalog struct {
	items  []Template
	byKey  map[string]Template
	byRefs map[string]Template
}

func Load() (*Catalog, error) {
	entries, err := fs.ReadDir(templateFiles, "templates")
	if err != nil {
		return nil, fmt.Errorf("read system policy templates: %w", err)
	}
	catalog := &Catalog{byKey: make(map[string]Template), byRefs: make(map[string]Template)}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := templateFiles.ReadFile("templates/" + entry.Name())
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
		if _, exists := catalog.byRefs[item.Reference()]; exists {
			return nil, fmt.Errorf("duplicate system policy template %q", item.Reference())
		}
		catalog.items = append(catalog.items, item)
		catalog.byRefs[item.Reference()] = item
		current, exists := catalog.byKey[item.Key]
		if !exists || compareVersion(item.Version, current.Version) > 0 {
			catalog.byKey[item.Key] = item
		}
	}
	if len(catalog.items) == 0 {
		return nil, errors.New("no system policy templates are embedded")
	}
	if _, ok := catalog.byKey[DefaultTemplateKey]; !ok {
		return nil, fmt.Errorf("default system policy template %q is missing", DefaultTemplateKey)
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

func (c *Catalog) Default() Template { return c.byKey[DefaultTemplateKey] }

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

// compareVersion compares the numeric parts of the simple template versions used
// by the built-in catalog. It deliberately does not implement a general semver
// parser because template versions are controlled by this repository.
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
