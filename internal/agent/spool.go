package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Fhwang0926/m-waf/internal/model"
)

type SpoolItem struct {
	Batch        model.EventBatch `json:"batch"`
	NextPosition AuditPosition    `json:"next_position"`
	NextOffset   int64            `json:"next_offset,omitempty"`
	path         string
}

type EventSpool struct {
	directory string
}

func NewEventSpool(directory string) *EventSpool { return &EventSpool{directory: directory} }

func (s *EventSpool) Put(batch model.EventBatch, nextPosition AuditPosition) (SpoolItem, error) {
	item := SpoolItem{Batch: batch, NextPosition: nextPosition, path: filepath.Join(s.directory, batch.BatchID+".json")}
	raw, err := json.Marshal(item)
	if err != nil {
		return SpoolItem{}, err
	}
	if err := atomicWrite(item.path, append(raw, '\n'), 0o600); err != nil {
		return SpoolItem{}, err
	}
	return item, nil
}

func (s *EventSpool) Pending() ([]SpoolItem, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	items := make([]SpoolItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.directory, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var item SpoolItem
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&item); err != nil {
			return nil, fmt.Errorf("decode event spool %s: %w", entry.Name(), err)
		}
		if item.NextPosition.Empty() && item.NextOffset > 0 {
			item.NextPosition.Offset = item.NextOffset
		}
		item.NextOffset = 0
		if item.Batch.BatchID == "" || item.NextPosition.Offset < 0 || entry.Name() != item.Batch.BatchID+".json" {
			return nil, fmt.Errorf("invalid event spool %s", entry.Name())
		}
		item.path = path
		items = append(items, item)
	}
	return items, nil
}

func (s *EventSpool) Remove(item SpoolItem) error {
	clean := filepath.Clean(item.path)
	base := filepath.Clean(s.directory) + string(filepath.Separator)
	if !strings.HasPrefix(clean, base) || filepath.Ext(clean) != ".json" {
		return errors.New("refuse to remove unsafe spool path")
	}
	return os.Remove(clean)
}

func (s *EventSpool) Stats() (int, int64, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	count := 0
	var size int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		count++
		size += info.Size()
	}
	return count, size, nil
}
