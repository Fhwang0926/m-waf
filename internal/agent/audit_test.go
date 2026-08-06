package agent

import (
	"os"
	"path/filepath"
	"strings"
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
	events, position, err := reader.ReadBatch(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].TransactionID != "one" {
		t.Fatalf("unexpected first batch: %#v", events)
	}
	if position.Offset != int64(len(first)+1) {
		t.Fatalf("partial line was committed: got %d", position.Offset)
	}
	if err := reader.Commit(position); err != nil {
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

func TestAuditReaderResetsCheckpointWhenLogIsReplaced(t *testing.T) {
	state := t.TempDir()
	logPath := filepath.Join(state, "audit.jsonl")
	line := `{"transaction":{"unique_id":"first","time_stamp":"2026-08-06T01:02:03Z","request":{"method":"GET","uri":"/one"},"response":{"http_code":403},"messages":[{"message":"blocked","details":{"ruleId":"942100","severity":"2"}}]}}`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reader := NewAuditReader(logPath, state)
	_, firstPosition, err := reader.ReadBatch(500)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Commit(firstPosition); err != nil {
		t.Fatal(err)
	}
	rotated := logPath + ".1"
	if err := os.Rename(logPath, rotated); err != nil {
		t.Fatal(err)
	}
	replacement := strings.Replace(line, "first", "second", 1)
	if err := os.WriteFile(logPath, []byte(replacement+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	events, secondPosition, err := reader.ReadBatch(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].TransactionID != "second" {
		t.Fatalf("replacement log was not read from the beginning: %#v", events)
	}
	if secondPosition.Inode == firstPosition.Inode && secondPosition.Device == firstPosition.Device {
		t.Fatal("replacement log identity did not change")
	}
}

func TestAuditReaderKeepsWholeLineAtBatchBoundary(t *testing.T) {
	state := t.TempDir()
	logPath := filepath.Join(state, "audit.jsonl")
	first := `{"transaction":{"unique_id":"one","time_stamp":"2026-08-06T01:02:03Z","request":{"method":"GET","uri":"/one"},"response":{"http_code":403},"messages":[{"message":"first","details":{"ruleId":"942100","severity":"2"}}]}}`
	second := `{"transaction":{"unique_id":"two","time_stamp":"2026-08-06T01:02:04Z","request":{"method":"GET","uri":"/two"},"response":{"http_code":403},"messages":[{"message":"second-a","details":{"ruleId":"942101","severity":"2"}},{"message":"second-b","details":{"ruleId":"942102","severity":"2"}}]}}`
	if err := os.WriteFile(logPath, []byte(first+"\n"+second+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	reader := NewAuditReader(logPath, state)
	events, firstPosition, err := reader.ReadBatch(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Message != "first" {
		t.Fatalf("unexpected first batch: %#v", events)
	}
	if firstPosition.Offset != int64(len(first)+1) {
		t.Fatalf("second line was consumed at batch boundary: got %d", firstPosition.Offset)
	}
	if err := reader.Commit(firstPosition); err != nil {
		t.Fatal(err)
	}

	events, secondPosition, err := reader.ReadBatch(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Message != "second-a" || events[1].Message != "second-b" {
		t.Fatalf("unexpected second batch: %#v", events)
	}
	if secondPosition.Offset != int64(len(first)+len(second)+2) {
		t.Fatalf("second line was not fully consumed: got %d", secondPosition.Offset)
	}
}

func TestAuditReaderContinuesOversizedTransaction(t *testing.T) {
	state := t.TempDir()
	logPath := filepath.Join(state, "audit.jsonl")
	line := `{"transaction":{"unique_id":"large","time_stamp":"2026-08-06T01:02:03Z","request":{"method":"GET","uri":"/large"},"response":{"http_code":403},"messages":[{"message":"one","details":{"ruleId":"1","severity":"2"}},{"message":"two","details":{"ruleId":"2","severity":"2"}},{"message":"three","details":{"ruleId":"3","severity":"2"}}]}}`
	if err := os.WriteFile(logPath, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	reader := NewAuditReader(logPath, state)
	first, firstPosition, err := reader.ReadBatch(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || firstPosition.Offset != 0 || firstPosition.MessageOffset != 2 {
		t.Fatalf("unexpected first part: events=%d position=%#v", len(first), firstPosition)
	}
	if err := reader.Commit(firstPosition); err != nil {
		t.Fatal(err)
	}
	second, secondPosition, err := reader.ReadBatch(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Message != "three" || secondPosition.Offset != int64(len(line)+1) || secondPosition.MessageOffset != 0 {
		t.Fatalf("unexpected second part: events=%#v position=%#v", second, secondPosition)
	}
}
