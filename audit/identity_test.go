package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	auditv1 "github.com/ledatu/csar-proto/csar/audit/v1"
)

func TestPrepareEventOwnsPayloadAndPreservesIdentity(t *testing.T) {
	original := &Event{
		ID:          "550E8400-E29B-41D4-A716-446655440000",
		CreatedAt:   time.Date(2026, 10, 8, 16, 0, 0, 123456789, time.FixedZone("MSK", 3*3600)),
		BeforeState: json.RawMessage(`{"x":1}`),
		AfterState:  json.RawMessage(`{"x":2}`),
		Metadata:    json.RawMessage(`{"x":3}`),
	}
	prepared, err := PrepareEvent(original)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ID != "550e8400-e29b-41d4-a716-446655440000" || prepared.CreatedAt.Nanosecond() != 123456000 {
		t.Fatalf("identity was not canonicalized: %+v", prepared)
	}
	if prepared.CreatedAt.Location() != time.UTC {
		t.Fatal("timestamp must use UTC")
	}
	for _, payload := range []json.RawMessage{original.BeforeState, original.AfterState, original.Metadata} {
		payload[5] = '9'
	}
	if string(prepared.BeforeState) != `{"x":1}` || string(prepared.AfterState) != `{"x":2}` || string(prepared.Metadata) != `{"x":3}` {
		t.Fatal("prepared event shares payload backing storage")
	}
	retry, err := PrepareEvent(prepared)
	if err != nil || retry.ID != prepared.ID || !retry.CreatedAt.Equal(prepared.CreatedAt) {
		t.Fatalf("retry changed identity: event=%+v err=%v", retry, err)
	}
}

func TestPrepareEventLegacyAndInvalidIDs(t *testing.T) {
	first, err := PrepareEvent(&Event{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareEvent(&Event{})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.CreatedAt.IsZero() || second.CreatedAt.IsZero() {
		t.Fatal("independent legacy emissions need independent IDs and timestamps")
	}
	for _, id := range []string{"invalid", "00000000-0000-0000-0000-000000000000"} {
		if _, err := PrepareEvent(&Event{ID: id}); err == nil {
			t.Fatalf("accepted invalid ID %q", id)
		}
	}
}

func TestPreparedEventProtoRoundTrip(t *testing.T) {
	event, err := PrepareEvent(&Event{Metadata: json.RawMessage(`{"operation":"update"}`)})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(EventToProto(event))
	if err != nil {
		t.Fatal(err)
	}
	var received auditv1.AuditEvent
	if err := proto.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	if received.Id != event.ID || !received.Timestamp.AsTime().Equal(event.CreatedAt) || string(received.Metadata) != string(event.Metadata) {
		t.Fatal("protobuf dropped identity, timestamp or payload")
	}
}

func TestClientPreparedSyncRetriesAndAsyncOwnership(t *testing.T) {
	transport := &sliceTransport{}
	client, err := NewClient(ClientConfig{Transport: transport, FallbackToLog: Bool(false)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareEvent(&Event{Action: "update"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := client.RecordSync(context.Background(), prepared); err != nil {
			t.Fatal(err)
		}
	}
	original := &Event{Action: "create", Metadata: json.RawMessage(`{"x":1}`)}
	client.Record(context.Background(), original)
	original.Metadata[5] = '9'
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.batch[0][0].ID != transport.batch[1][0].ID || !transport.batch[0][0].CreatedAt.Equal(transport.batch[1][0].CreatedAt) {
		t.Fatal("sync retry changed prepared identity")
	}
	var found bool
	for _, batch := range transport.batch {
		for _, event := range batch {
			if event.Action == "create" {
				found = true
				if event.ID == "" || event.CreatedAt.IsZero() || string(event.Metadata) != `{"x":1}` {
					t.Fatal("async emission lost identity or owns caller memory")
				}
			}
		}
	}
	if !found {
		t.Fatal("async event was not flushed")
	}
}

func TestClientConcurrentRecordAndClose(t *testing.T) {
	client, err := NewClient(ClientConfig{Transport: &sliceTransport{}, FallbackToLog: Bool(false)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				client.Record(context.Background(), &Event{Action: "update"})
			}
		})
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
}
