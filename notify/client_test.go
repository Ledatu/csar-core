package notify

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
	batch  [][]*Notification
	closed int
}

func (s *sliceTransport) Send(_ context.Context, notifications []*Notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := make([]*Notification, len(notifications))
	for i, notification := range notifications {
		cp[i] = cloneNotification(notification)
	}
	s.batch = append(s.batch, cp)
	return nil
}

func (s *sliceTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func TestHTTPTransportAccepted(t *testing.T) {
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
			Notifications []Notification `json:"notifications"`
		}
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Notifications) != 1 || body.Notifications[0].Topic != "platform.devlog" {
			t.Fatalf("unexpected body: %s", b)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	tr := NewHTTPTransport(srv.Client(), srv.URL)
	err := tr.Send(context.Background(), []*Notification{{
		Topic: "platform.devlog",
		Title: "released",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientFlushesBatch(t *testing.T) {
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
	first := &Notification{
		Topic:      "platform.devlog",
		Title:      "a",
		Recipients: []string{"u1"},
		Metadata:   map[string]string{"k": "v"},
		Channels:   []Channel{ChannelSite},
	}
	c.Record(ctx, first)
	first.Recipients[0] = "mutated"
	first.Metadata["k"] = "changed"
	first.Channels[0] = ChannelTelegram
	c.Record(ctx, &Notification{Topic: "platform.audit", Title: "b"})

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
	var cloned *Notification
	for _, batch := range st.batch {
		for _, notification := range batch {
			seen += notification.Title
			if notification.Title == "a" {
				cloned = notification
			}
		}
	}
	if !strings.Contains(seen, "a") || !strings.Contains(seen, "b") {
		t.Fatalf("missing notifications, got %q", seen)
	}
	if cloned == nil {
		t.Fatal("missing cloned notification")
	}
	if cloned.Recipients[0] != "u1" {
		t.Fatalf("recipients not cloned: %+v", cloned.Recipients)
	}
	if cloned.Metadata["k"] != "v" {
		t.Fatalf("metadata not cloned: %+v", cloned.Metadata)
	}
	if cloned.Channels[0] != ChannelSite {
		t.Fatalf("channels not cloned: %+v", cloned.Channels)
	}
	if st.closed != 1 {
		t.Fatalf("close count %d", st.closed)
	}
}

func TestRecordSyncTransport(t *testing.T) {
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

	if err := c.RecordSync(context.Background(), &Notification{
		Topic: "admin.audit",
		Title: "x",
	}); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.batch) != 1 || len(st.batch[0]) != 1 || st.batch[0][0].Title != "x" {
		t.Fatalf("sync send: got %+v", st.batch)
	}
}
