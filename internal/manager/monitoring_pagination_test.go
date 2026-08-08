package manager

import (
	"testing"
	"time"
)

func TestEventCursorRoundTrip(t *testing.T) {
	event := EventRecord{ID: 42, OccurredAt: time.Date(2026, 8, 8, 1, 2, 3, 456000000, time.UTC)}
	encoded := encodeEventCursor(event, eventCursorBefore)
	at, id, direction, ok := decodeEventCursor(encoded)
	if !ok || id != event.ID || direction != eventCursorBefore || !at.Equal(event.OccurredAt) {
		t.Fatalf("decoded cursor: ok=%v id=%d direction=%q at=%s", ok, id, direction, at)
	}
	if _, _, _, ok := decodeEventCursor("not-a-cursor"); ok {
		t.Fatal("invalid cursor was accepted")
	}
}

func TestPaginateEventRecordsForward(t *testing.T) {
	items := eventRecordsWithIDs(300, 200, -1)
	result := paginateEventRecords(items, 100, 1, eventCursorBefore)
	if !result.HasPrevious || !result.HasNext || len(result.Items) != 100 {
		t.Fatalf("page flags: previous=%v next=%v length=%d", result.HasPrevious, result.HasNext, len(result.Items))
	}
	if result.Items[0].ID != 300 || result.Items[len(result.Items)-1].ID != 201 {
		t.Fatalf("unexpected page boundary: first=%d last=%d", result.Items[0].ID, result.Items[len(result.Items)-1].ID)
	}
}

func TestPaginateEventRecordsBackward(t *testing.T) {
	items := eventRecordsWithIDs(101, 201, 1)
	result := paginateEventRecords(items, 100, 2, eventCursorAfter)
	if !result.HasPrevious || !result.HasNext || len(result.Items) != 100 {
		t.Fatalf("page flags: previous=%v next=%v length=%d", result.HasPrevious, result.HasNext, len(result.Items))
	}
	if result.Items[0].ID != 200 || result.Items[len(result.Items)-1].ID != 101 {
		t.Fatalf("unexpected page boundary: first=%d last=%d", result.Items[0].ID, result.Items[len(result.Items)-1].ID)
	}

	firstPage := paginateEventRecords(eventRecordsWithIDs(201, 300, 1), 100, 1, eventCursorAfter)
	if firstPage.HasPrevious || !firstPage.HasNext || firstPage.Items[0].ID != 300 || firstPage.Items[len(firstPage.Items)-1].ID != 201 {
		t.Fatalf("unexpected first page: previous=%v next=%v first=%d last=%d", firstPage.HasPrevious, firstPage.HasNext, firstPage.Items[0].ID, firstPage.Items[len(firstPage.Items)-1].ID)
	}
}

func eventRecordsWithIDs(from, to, step int) []EventRecord {
	items := make([]EventRecord, 0)
	at := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	for id := from; id != to; id += step {
		items = append(items, EventRecord{ID: uint64(id), OccurredAt: at})
	}
	return items
}
