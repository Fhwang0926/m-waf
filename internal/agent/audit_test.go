package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditReaderLeavesPartialJSONUncommitted(t *testing.T) {
	state := t.TempDir()
	logPath := filepath.Join(state, "audit.jsonl")
	first := `{"transaction":{"unique_id":"one","time_stamp":"2026-08-06T01:02:03Z","request":{"method":"GET","uri":"/one"},"response":{"http_code":403},"messages":[{"message":"blocked","details":{"ruleId":"942100","severity":"2"}}]}}`
	second := `{"transaction":{"unique_id":"two","time_stamp":"2026-08-06T01:02:04Z","request":{"method":"POST","uri":"/two"},"response":{"http_code":200},"messages":[{"message":"detected","details":{"ruleId":"920100","severity":"3"}}]}}`
	partial := second[:len(second)/2]
	if err := os.WriteFile(logPath, []byte(first+"\n"+partial), 0o640); err != nil {
		t.Fatal(err)
	}
	reader := NewAuditReader(logPath, state)
	events, offset, err := reader.ReadBatch(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].TransactionID != "one" {
		t.Fatalf("unexpected first batch: %#v", events)
	}
	if offset != int64(len(first)+1) {
		t.Fatalf("partial line was committed: got %d", offset)
	}
	if err := reader.Commit(offset); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(second[len(partial):] + "\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	events, _, err = reader.ReadBatch(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].TransactionID != "two" {
		t.Fatalf("unexpected second batch: %#v", events)
	}
}
