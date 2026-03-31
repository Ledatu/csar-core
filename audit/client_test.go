package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type sliceTransport struct {
	mu     sync.Mutex
	batch  [][]*Event
	closed int
}

func (s *sliceTransport) Send(_ context.Context, events []*Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*Event, len(events))
	copy(cp, events)
	s.batch = append(s.batch, cp)
	return nil
}

func (s *sliceTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func TestHTTPTransport_Accepted(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ingest" {
			t.Errorf("path %q", r.URL.Path)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Events []Event `json:"events"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Events) != 1 || body.Events[0].Action != "create" {
			t.Fatalf("unexpected body: %s", b)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	tr := NewHTTPTransport(srv.Client(), srv.URL)
	ctx := context.Background()
	err := tr.Send(ctx, []*Event{{Action: "create", Actor: "u1", TargetType: "r", ScopeType: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClient_FlushesBatch(t *testing.T) {
	t.Parallel()

	st := &sliceTransport{}
	c, err := NewClient(ClientConfig{
		Transport:     st,
		BufferSize:    10,
		FlushTimeout:  80 * time.Millisecond,
		Workers:       1,
		FallbackToLog: Bool(false),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	c.Record(ctx, &Event{Action: "a", Actor: "1", TargetType: "r", ScopeType: "s"})
	c.Record(ctx, &Event{Action: "b", Actor: "2", TargetType: "r", ScopeType: "s"})

	time.Sleep(150 * time.Millisecond)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.batch) == 0 {
		t.Fatal("expected at least one batch")
	}
	var seen string
	for _, b := range st.batch {
		for _, e := range b {
			seen += e.Action
		}
	}
	if !strings.Contains(seen, "a") || !strings.Contains(seen, "b") {
		t.Fatalf("missing events, got %q", seen)
	}
	if st.closed != 1 {
		t.Fatalf("close count %d", st.closed)
	}
}

func TestRecordSync_Transport(t *testing.T) {
	t.Parallel()

	st := &sliceTransport{}
	c, err := NewClient(ClientConfig{
		Transport:     st,
		FallbackToLog: Bool(false),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if err := c.RecordSync(context.Background(), &Event{
		Action: "x", Actor: "y", TargetType: "r", ScopeType: "s",
	}); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.batch) != 1 || len(st.batch[0]) != 1 || st.batch[0][0].Action != "x" {
		t.Fatalf("sync send: got %+v", st.batch)
	}
}
