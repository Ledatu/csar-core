package clientmetrics

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ledatu/csar-core/httpx/jsonstream"
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

// DecodeObject observes element-streaming separately from buffered JSON helpers.
// Read and parse overlap, so its elapsed duration must not be interpreted as CPU
// time or added to transport/body-read timing. The caller owns body cleanup.
func DecodeObject[T any](client *http.Client, r io.Reader, maxBytes int64, fields func(*T) []jsonstream.Field) (T, jsonstream.Info, error) {
	m, scope := source(client)
	if m == nil {
		return jsonstream.DecodeObject(r, maxBytes, fields)
	}
	start := time.Now()
	out, info, err := jsonstream.DecodeObject(r, maxBytes, fields)
	result := "ok"
	switch {
	case info.ReadError != nil:
		result = "read_error"
	case errors.Is(err, jsonstream.ErrTooLarge):
		result = "too_large"
	case err != nil:
		result = "decode_error"
	}
	m.jsonStreamDuration.WithLabelValues(scope, result).Observe(time.Since(start).Seconds())
	m.jsonStreamBytes.WithLabelValues(scope, result).Observe(float64(info.BytesRead))
	return out, info, err
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
