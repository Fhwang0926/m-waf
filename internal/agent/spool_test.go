package agent

import (
	"testing"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

func TestEventSpoolRoundTrip(t *testing.T) {
	spool := NewEventSpool(t.TempDir())
	batch := model.EventBatch{BatchID: "batch-1", Events: []model.SecurityEvent{{EventID: "event-1", OccurredAt: time.Now().UTC()}}}
	created, err := spool.Put(batch, 123)
	if err != nil {
		t.Fatal(err)
	}
	items, err := spool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Batch.BatchID != batch.BatchID || items[0].NextOffset != 123 {
		t.Fatalf("unexpected spool items: %#v", items)
	}
	count, size, err := spool.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || size == 0 {
		t.Fatalf("unexpected spool stats: %d %d", count, size)
	}
	if err := spool.Remove(created); err != nil {
		t.Fatal(err)
	}
	items, err = spool.Pending()
	if err != nil || len(items) != 0 {
		t.Fatalf("spool was not removed: %#v %v", items, err)
	}
}
