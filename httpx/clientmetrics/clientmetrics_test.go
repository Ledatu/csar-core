package clientmetrics_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ledatu/csar-core/httpx/clientmetrics"
	"github.com/ledatu/csar-core/httpx/clientx"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func setup(t *testing.T) (*prometheus.Registry, *clientmetrics.Metrics) {
	t.Helper()
	r := prometheus.NewRegistry()
	m, err := clientmetrics.New(r)
	if err != nil {
		t.Fatal(err)
	}
	return r, m
}
func sample(t *testing.T, r *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()
	families, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.Metric {
			match := true
			for k, v := range labels {
				found := false
				for _, l := range m.Label {
					if l.GetName() == k && l.GetValue() == v {
						found = true
					}
				}
				if !found {
					match = false
				}
			}
			if match {
				return m
			}
		}
	}
	return nil
}
func histogram(t *testing.T, r *prometheus.Registry, name string, labels map[string]string) *dto.Histogram {
	t.Helper()
	m := sample(t, r, name, labels)
	if m == nil {
		t.Fatalf("missing histogram %s %v", name, labels)
	}
	return m.Histogram
}
func doRead(t *testing.T, c *http.Client, req *http.Request) []byte {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}
func request(t *testing.T, method, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRepresentationAvailabilityPreservesNativeGzip(t *testing.T) {
	data := []byte(`{"items":"` + strings.Repeat("abc", 1000) + `"}`)
	var packed bytes.Buffer
	z := gzip.NewWriter(&packed)
	if _, err := z.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(packed.Bytes())
	}))
	defer server.Close()
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic", true: "explicit"}[explicit], func(t *testing.T) {
			reg, m := setup(t)
			c := clientmetrics.WrapClient(server.Client(), m, clientmetrics.ScopeRouter)
			req := request(t, "GET", server.URL+"/seller/private-id?key=secret")
			if explicit {
				req.Header.Set("Accept-Encoding", "gzip")
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			known, unknown := "decoded", "wire"
			want := data
			if explicit {
				known, unknown = "wire", "decoded"
				want = packed.Bytes()
				if resp.Uncompressed || resp.Header.Get("Content-Encoding") != "gzip" {
					t.Fatal("explicit gzip changed")
				}
			} else if !resp.Uncompressed || resp.Header.Get("Content-Encoding") != "" {
				t.Fatal("native decompression changed")
			}
			if !bytes.Equal(raw, want) {
				t.Fatal("response changed")
			}
			h := histogram(t, reg, "csar_client_body_bytes", map[string]string{"kind": known})
			if h.GetSampleSum() != float64(len(want)) || h.GetSampleCount() != 1 {
				t.Fatalf("wrong consumed bytes: %v", h)
			}
			if sample(t, reg, "csar_client_body_bytes", map[string]string{"kind": unknown}) != nil {
				t.Fatal("fabricated unavailable representation bytes")
			}
			counter := sample(t, reg, "csar_client_body_observations_total", map[string]string{"kind": unknown, "availability": "unknown"})
			if counter == nil || counter.Counter.GetValue() != 1 {
				t.Fatal("unknown availability missing")
			}
			families, err := reg.Gather()
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range families {
				for _, metric := range f.Metric {
					for _, label := range metric.Label {
						if strings.Contains(label.GetValue(), "private-id") || strings.Contains(label.GetValue(), "secret") || strings.Contains(label.GetValue(), "seller") {
							t.Fatal("sensitive metric label")
						}
					}
				}
			}
		})
	}
}

func TestJSONReadLimitCountsDrainSeparately(t *testing.T) {
	reg, m := setup(t)
	body := strings.Repeat("x", 100)
	base := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	c := clientmetrics.WrapClient(base, m, clientmetrics.ScopeRouter)
	_, err := clientx.DoJSON[map[string]any](context.Background(), request(t, "GET", "https://router.invalid/read"), clientx.Options{Client: c, MaxResponseBytes: 8})
	if !errors.Is(err, clientx.ErrResponseTooLarge) || err.Status != 200 {
		t.Fatalf("limit behavior changed: %v", err)
	}
	if got := histogram(t, reg, "csar_client_json_buffer_bytes", nil).GetSampleSum(); got != 9 {
		t.Fatalf("buffer bytes=%v, want limit+1", got)
	}
	for _, kind := range []string{"wire", "decoded"} {
		if got := histogram(t, reg, "csar_client_body_bytes", map[string]string{"kind": kind, "completion": "eof"}).GetSampleSum(); got != 100 {
			t.Fatalf("%s consumed=%v, drain missing", kind, got)
		}
	}
	if sample(t, reg, "csar_client_json_duration_seconds", map[string]string{"phase": "decode"}) != nil {
		t.Fatal("oversized body decoded")
	}
}

func TestJSONDecodePreservesErrorAndDefault(t *testing.T) {
	plain := &http.Client{}
	if clientmetrics.WrapClient(plain, nil, clientmetrics.ScopeRouter) != plain {
		t.Fatal("default path wrapped")
	}
	reg, m := setup(t)
	c := clientmetrics.WrapClient(plain, m, clientmetrics.ScopeRouter)
	var out map[string]int
	if err := clientmetrics.DecodeJSON(c, []byte(`{"a":1}`), &out); err != nil || out["a"] != 1 {
		t.Fatalf("valid decode: %v", err)
	}
	if err := clientmetrics.DecodeJSON(c, []byte(`{`), &out); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	for _, result := range []string{"ok", "error"} {
		if h := histogram(t, reg, "csar_client_json_duration_seconds", map[string]string{"phase": "decode", "result": result}); h.GetSampleCount() != 1 {
			t.Fatalf("wrong decode count %v", h)
		}
	}
}

type failedReader struct{}

func (failedReader) Read(p []byte) (int, error) { return copy(p, "oops"), io.ErrUnexpectedEOF }
func (failedReader) Close() error               { return nil }

func TestReadFailureEarlyCloseAndTransportError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       io.ReadCloser
		read       bool
		completion string
		wantBytes  float64
	}{{"read_error", failedReader{}, true, "read_error", 4}, {"early_close", io.NopCloser(strings.NewReader("unread")), false, "early_close", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			reg, m := setup(t)
			c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: tc.body}, nil
			})}, m, clientmetrics.ScopeRouter)
			resp, err := c.Do(request(t, "GET", "https://router.invalid"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.read {
				_, err = io.ReadAll(resp.Body)
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("read error changed: %v", err)
				}
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			h := histogram(t, reg, "csar_client_body_bytes", map[string]string{"kind": "decoded", "completion": tc.completion})
			if h.GetSampleSum() != tc.wantBytes || h.GetSampleCount() != 1 {
				t.Fatalf("wrong incomplete observation: %v", h)
			}
		})
	}
	reg, m := setup(t)
	c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })}, m, clientmetrics.Scope("account-secret"))
	_, err := c.Do(request(t, "CUSTOM-secret", "https://sensitive.invalid/private-id"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline error changed")
	}
	h := histogram(t, reg, "csar_client_request_duration_seconds", map[string]string{"scope": "other", "method": "OTHER", "result": "deadline"})
	if h.GetSampleCount() != 1 {
		t.Fatal("normalized labels missing")
	}
	if sample(t, reg, "csar_client_body_bytes", nil) != nil {
		t.Fatal("fabricated body for transport failure")
	}
}

type idleTransport struct{ closed bool }

func (t *idleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody}, nil
}
func (t *idleTransport) CloseIdleConnections() { t.closed = true }

func TestClientSettingsAndRepeatedWrapping(t *testing.T) {
	reg, m := setup(t)
	base := &idleTransport{}
	redirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	original := &http.Client{Transport: base, Timeout: 3 * time.Second, CheckRedirect: redirect}
	c := clientmetrics.WrapClient(original, m, clientmetrics.ScopeRouter)
	if c == original || original.Transport != base || c.Timeout != original.Timeout || c.CheckRedirect == nil {
		t.Fatal("client settings changed")
	}
	twice := clientmetrics.WrapClient(c, m, clientmetrics.ScopeRouter)
	if twice != c {
		t.Fatal("duplicate wrapper")
	}
	doRead(t, twice, request(t, "GET", "https://router.invalid"))
	twice.CloseIdleConnections()
	if !base.closed {
		t.Fatal("pool cleanup lost")
	}
	if h := histogram(t, reg, "csar_client_request_duration_seconds", nil); h.GetSampleCount() != 1 {
		t.Fatal("request double-counted")
	}
	if _, err := clientmetrics.New(reg); err == nil {
		t.Fatal("duplicate collector accepted")
	}
	if _, err := clientmetrics.New(nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

type blockedBody struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *blockedBody) Read(p []byte) (int, error) {
	close(b.started)
	<-b.closed
	return copy(p, "tail"), io.ErrUnexpectedEOF
}
func (b *blockedBody) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestConcurrentReadCloseIncludesInFlightBytes(t *testing.T) {
	reg, m := setup(t)
	body := &blockedBody{started: make(chan struct{}), closed: make(chan struct{})}
	c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	})}, m, clientmetrics.ScopeRouter)
	resp, err := c.Do(request(t, "GET", "https://router.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = io.ReadAll(resp.Body); close(done) }()
	<-body.started
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close failed to unblock Read")
	}
	h := histogram(t, reg, "csar_client_body_bytes", map[string]string{"kind": "decoded", "completion": "early_close"})
	if h.GetSampleCount() != 1 || h.GetSampleSum() != 4 {
		t.Fatalf("in-flight bytes lost or duplicate observation: %v", h)
	}
}

type upgradeBody struct{ bytes.Buffer }

func (*upgradeBody) Close() error { return nil }
func TestUpgradeBodyRetainsWriter(t *testing.T) {
	_, m := setup(t)
	body := &upgradeBody{}
	c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 101, Header: make(http.Header), Body: body}, nil
	})}, m, clientmetrics.ScopeOther)
	resp, err := c.Do(request(t, "GET", "https://router.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("upgrade writer lost")
	}
	if _, err := rw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if body.String() != "hello" {
		t.Fatal("upgrade write changed")
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedJSONReadIncludesSubsequentCallerDrain(t *testing.T) {
	reg, m := setup(t)
	c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: failedReader{}}, nil
	})}, m, clientmetrics.ScopeRouter)
	_, err := clientx.DoJSON[map[string]any](context.Background(), request(t, "GET", "https://router.invalid"), clientx.Options{Client: c})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error changed: %v", err)
	}
	if h := histogram(t, reg, "csar_client_json_buffer_bytes", nil); h.GetSampleSum() != 4 {
		t.Fatalf("JSON partial buffer=%v", h)
	}
	if h := histogram(t, reg, "csar_client_body_bytes", map[string]string{"kind": "decoded", "completion": "read_error"}); h.GetSampleSum() != 8 {
		t.Fatalf("caller error drain not counted: %v", h)
	}
}

func TestClientxDefaultClientPhaseHooksAndDisabledAllocations(t *testing.T) {
	plain := &http.Client{}
	payload := []byte(`{"n":1}`)
	var out struct {
		N int `json:"n"`
	}
	direct := testing.AllocsPerRun(50, func() {
		if err := json.Unmarshal(payload, &out); err != nil {
			panic(err)
		}
	})
	disabled := testing.AllocsPerRun(50, func() {
		if err := clientmetrics.DecodeJSON(plain, payload, &out); err != nil {
			panic(err)
		}
	})
	if disabled > direct {
		t.Fatalf("disabled decode adds allocations: direct=%v observer=%v", direct, disabled)
	}
	if n := testing.AllocsPerRun(50, func() { _ = clientmetrics.WrapClient(plain, nil, clientmetrics.ScopeRouter) }); n != 0 {
		t.Fatalf("disabled wrapping allocates: %v", n)
	}
	reg, m := setup(t)
	c := clientmetrics.WrapClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload))}, nil
	})}, m, clientmetrics.ScopeRouter)
	previous := http.DefaultClient
	http.DefaultClient = c
	defer func() { http.DefaultClient = previous }()
	value, err := clientx.DoJSON[map[string]int](context.Background(), request(t, "GET", "https://router.invalid"), clientx.Options{})
	if err != nil || value["n"] != 1 {
		t.Fatalf("default client behavior changed: %v", err)
	}
	for _, phase := range []string{"read", "decode"} {
		if h := histogram(t, reg, "csar_client_json_duration_seconds", map[string]string{"phase": phase}); h.GetSampleCount() != 1 {
			t.Fatalf("missing default-client %s", phase)
		}
	}
	if h := histogram(t, reg, "csar_client_response_headers_duration_seconds", nil); h.GetSampleCount() != 1 {
		t.Fatal("header duration missing")
	}
}
