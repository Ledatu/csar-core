package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPTransport POSTs JSON batches to {baseURL}/ingest.
// The HTTP client may carry custom auth (Bearer, mTLS, etc.) via Transport or hooks.
type HTTPTransport struct {
	client    *http.Client
	ingestURL string
}

type httpIngestBody struct {
	Events []*Event `json:"events"`
}

// NewHTTPTransport builds a transport. baseURL is trimmed and "/ingest" is appended.
// If client is nil, http.DefaultClient is used.
func NewHTTPTransport(client *http.Client, baseURL string) *HTTPTransport {
	if client == nil {
		client = http.DefaultClient
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return &HTTPTransport{
		client:    client,
		ingestURL: base + "/ingest",
	}
}

// Send implements Transport.
func (t *HTTPTransport) Send(ctx context.Context, events []*Event) error {
	if t == nil || len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(httpIngestBody{Events: events})
	if err != nil {
		return fmt.Errorf("marshal audit ingest body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.ingestURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build audit ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit ingest request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("audit ingest: unexpected status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
}

// Close implements Transport.
func (*HTTPTransport) Close() error {
	return nil
}
