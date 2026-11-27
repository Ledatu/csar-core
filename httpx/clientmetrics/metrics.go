// Package clientmetrics provides opt-in, bounded-cardinality outbound HTTP and
// JSON measurements without changing transport, retry or decoding behavior.
package clientmetrics

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Scope identifies a fixed infrastructure boundary, never a path or account.
type Scope string

const (
	ScopeRouter Scope = "router"
	ScopeSTS    Scope = "sts"
	ScopeOther  Scope = "other"
)

func scopeLabel(scope Scope) string {
	switch scope {
	case ScopeRouter, ScopeSTS:
		return string(scope)
	default:
		return string(ScopeOther)
	}
}

// Metrics belongs to one application registry. Construct it once with New.
// No collector is registered globally, and no request URL, error text, account,
// host or business identifier is used as a metric label.
type Metrics struct {
	requestDuration    *prometheus.HistogramVec
	headerDuration     *prometheus.HistogramVec
	bodyReadDuration   *prometheus.HistogramVec
	bodyBytes          *prometheus.HistogramVec
	bodyAvailability   *prometheus.CounterVec
	jsonDuration       *prometheus.HistogramVec
	jsonBufferBytes    *prometheus.HistogramVec
	jsonStreamDuration *prometheus.HistogramVec
	jsonStreamBytes    *prometheus.HistogramVec
	collectors         []prometheus.Collector
}

// New registers one collector bundle atomically with reg. A nil registerer is
// rejected rather than silently using the default/global registry.
func New(reg prometheus.Registerer) (*Metrics, error) {
	if reg == nil {
		return nil, errors.New("clientmetrics: registerer is required")
	}
	bytesBuckets := []float64{0, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 268435456}
	m := &Metrics{
		headerDuration:     prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_response_headers_duration_seconds", Help: "Outbound RoundTrip time until response headers/error, including connection/TLS and outer-wrapper authentication/retries where applicable; not provider-only latency.", Buckets: prometheus.DefBuckets}, []string{"scope", "method", "status_class", "result"}),
		requestDuration:    prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_request_duration_seconds", Help: "Outbound HTTP time until body EOF, read error or close, including caller pauses and outer-wrapper authentication/retries; not server latency.", Buckets: prometheus.DefBuckets}, []string{"scope", "method", "status_class", "result"}),
		bodyReadDuration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_body_read_duration_seconds", Help: "Sum of time inside response-body Read calls, including transport decoding; not pure network time.", Buckets: prometheus.DefBuckets}, []string{"scope", "completion"}),
		bodyBytes:          prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_body_bytes", Help: "Response representation bytes consumed, including caller drains, only when that representation is observable; excludes headers, framing, TLS and hidden retry bodies.", Buckets: bytesBuckets}, []string{"scope", "kind", "completion"}),
		bodyAvailability:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "csar_client_body_observations_total", Help: "Availability of consumed wire-representation and decoded-representation byte counts; unknown never creates a zero byte sample."}, []string{"scope", "kind", "availability", "completion"}),
		jsonDuration:       prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_json_duration_seconds", Help: "Time inside the shared JSON buffered read or json.Unmarshal helper; excludes business mapping and database work.", Buckets: prometheus.DefBuckets}, []string{"scope", "phase", "result"}),
		jsonBufferBytes:    prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_json_buffer_bytes", Help: "Bytes materialized by the shared JSON read before status/size validation, including a possible limit-plus-one sentinel or partial failed read; excludes later drain bytes.", Buckets: bytesBuckets}, []string{"scope", "result"}),
		jsonStreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_json_stream_duration_seconds", Help: "Combined bounded element-streaming read and JSON decode elapsed time; includes input waits and decoding, excludes business mapping/database work, not pure CPU time.", Buckets: prometheus.DefBuckets}, []string{"scope", "result"}),
		jsonStreamBytes:    prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "csar_client_json_stream_bytes", Help: "Input representation bytes consumed by the bounded element-streaming decoder, normally decoded JSON after transport decompression, including partial reads/limit-plus-one sentinel; not buffered bytes, retained heap, accepted business data or a compressed wire measurement.", Buckets: bytesBuckets}, []string{"scope", "result"}),
	}
	m.collectors = []prometheus.Collector{m.requestDuration, m.headerDuration, m.bodyReadDuration, m.bodyBytes, m.bodyAvailability, m.jsonDuration, m.jsonBufferBytes, m.jsonStreamDuration, m.jsonStreamBytes}
	if err := reg.Register(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range m.collectors {
		c.Describe(ch)
	}
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	for _, c := range m.collectors {
		c.Collect(ch)
	}
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}
func statusLabel(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "none"
	}
}

func (m *Metrics) recordBody(scope, method string, status int, start, end time.Time, readTime time.Duration, n int64, completion string, wireKnown, decodedKnown bool) {
	result := "ok"
	switch completion {
	case "read_error":
		result = "read_error"
	case "early_close":
		result = "incomplete"
	default:
		if status >= 400 {
			result = "http_error"
		}
	}
	m.requestDuration.WithLabelValues(scope, method, statusLabel(status), result).Observe(end.Sub(start).Seconds())
	m.bodyReadDuration.WithLabelValues(scope, completion).Observe(readTime.Seconds())
	for _, item := range []struct {
		kind  string
		known bool
	}{{"wire", wireKnown}, {"decoded", decodedKnown}} {
		available := "unknown"
		if item.known {
			available = "known"
			m.bodyBytes.WithLabelValues(scope, item.kind, completion).Observe(float64(n))
		}
		m.bodyAvailability.WithLabelValues(scope, item.kind, available, completion).Inc()
	}
}

func representation(resp *http.Response) (wireKnown, decodedKnown bool) {
	if resp.Uncompressed {
		return false, true
	}
	// Content-Encoding is a list-valued field and may span multiple header
	// lines. A first empty/identity line does not hide a later gzip coding.
	for _, line := range resp.Header.Values("Content-Encoding") {
		for _, coding := range strings.Split(line, ",") {
			coding = strings.TrimSpace(coding)
			if coding != "" && !strings.EqualFold(coding, "identity") {
				return true, false
			}
		}
	}
	return true, true
}
