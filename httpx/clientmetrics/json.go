package clientmetrics

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// ReadAll is io.ReadAll with optional JSON-buffer timing and byte observation.
// Callers retain ownership of bounds, response status validation and cleanup.
// Counts cover the returned buffer, including partial failures/limit sentinels,
// rather than the complete response or bytes accepted by a business model.
func ReadAll(client *http.Client, r io.Reader) ([]byte, error) {
	m, scope := source(client)
	if m == nil {
		return io.ReadAll(r)
	}
	start := time.Now()
	raw, err := io.ReadAll(r)
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.jsonDuration.WithLabelValues(scope, "read", result).Observe(time.Since(start).Seconds())
	m.jsonBufferBytes.WithLabelValues(scope, result).Observe(float64(len(raw)))
	return raw, err
}

// DecodeJSON is json.Unmarshal with opt-in timing from the instrumented client.
// It records only this decode, not caller mapping/deduplication or database work.
// Use it for manual decoding outside clientx to share the same measurements.
func DecodeJSON(client *http.Client, data []byte, out any) error {
	m, scope := source(client)
	if m == nil {
		return json.Unmarshal(data, out)
	}
	start := time.Now()
	err := json.Unmarshal(data, out)
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.jsonDuration.WithLabelValues(scope, "decode", result).Observe(time.Since(start).Seconds())
	return err
}
