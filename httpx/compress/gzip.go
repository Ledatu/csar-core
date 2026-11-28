// Package compress provides opt-in streaming HTTP response compression.
package compress

import (
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Options configures Gzip. The zero value uses a 1 KiB prefix and gzip.BestSpeed.
type Options struct {
	// MinBytes is the maximum prefix buffered before committing gzip. Values
	// outside 1..64 KiB use 1 KiB, keeping per-request buffering bounded.
	MinBytes int
	// OnError observes compressor finalization errors after a response is committed.
	OnError func(error)
}

// Gzip compresses successful JSON responses when the client accepts gzip.
// Already-encoded, cookie-setting, no-store, no-transform, partial, HEAD and
// upgrade responses pass through. An explicit flush commits the negotiated
// encoding immediately, even below MinBytes, instead of delaying the stream.
// It does not decompress requests or upstream responses, or enable itself in
// any server. Apply it outside response transforms and representation caches.
func Gzip(next http.Handler, opts Options) http.Handler {
	return GzipMiddleware(opts)(next)
}

// GzipMiddleware creates an explicitly enabled middleware factory. Reuse the
// factory when choosing handlers at dispatch time to retain the encoder pool.
// Client encoding support only negotiates an enabled policy; it does not opt in
// a server, route, URL convention or cache hit to compression.
func GzipMiddleware(opts Options) func(http.Handler) http.Handler {
	minBytes := opts.MinBytes
	if minBytes < 1 || minBytes > 64<<10 {
		minBytes = 1 << 10
	}
	var pool sync.Pool
	pool.New = func() any {
		// BestSpeed is a compile-time valid compression level.
		zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		return zw
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead || r.Header.Get("Range") != "" ||
				r.Header.Get("Upgrade") != "" || directive(strings.Join(r.Header.Values("Cache-Control"), ","), "no-transform") {
				next.ServeHTTP(w, r)
				return
			}
			cw := &writer{ResponseWriter: w, minBytes: minBytes, accept: acceptsGzip(r.Header.Values("Accept-Encoding")), pool: &pool}
			defer func() {
				if cw.gz != nil {
					cw.gz.Reset(io.Discard)
					pool.Put(cw.gz)
				}
			}()
			next.ServeHTTP(cw, r)
			if err := cw.finish(); err != nil && opts.OnError != nil {
				opts.OnError(err)
			}
		})
	}
}

type writer struct {
	http.ResponseWriter
	pool     *sync.Pool
	gz       *gzip.Writer
	prefix   []byte
	headers  http.Header
	minBytes int
	code     int
	accept   bool
	started  bool
}

func (w *writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *writer) WriteHeader(code int) {
	if w.code != 0 {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.code = code
	if !w.eligible() {
		if code == http.StatusNotModified || hasContentEncoding(w.Header()) {
			varyEncoding(w.Header())
		}
		w.start(false)
		return
	}
	// WriteHeader freezes ordinary headers even while a small prefix is held.
	w.headers = w.Header().Clone()
}

func (w *writer) eligible() bool {
	h := w.Header()
	if w.code != http.StatusOK || hasContentEncoding(h) || h.Get("Content-Range") != "" ||
		len(h.Values("Set-Cookie")) > 0 || directive(strings.Join(h.Values("Cache-Control"), ","), "no-transform") ||
		directive(strings.Join(h.Values("Cache-Control"), ","), "no-store") {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

func hasContentEncoding(h http.Header) bool {
	for _, line := range h.Values("Content-Encoding") {
		if strings.TrimSpace(line) != "" {
			return true
		}
	}
	return false
}

func (w *writer) Write(body []byte) (int, error) {
	if w.code == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.started {
		return w.write(body)
	}
	// No client support means no prefix copy or encoding work. Vary still
	// distinguishes this identity response from the negotiated representation.
	if !w.accept {
		w.start(false)
		return w.write(body)
	}
	if len(w.prefix)+len(body) < w.minBytes {
		w.prefix = append(w.prefix, body...)
		return len(body), nil
	}
	w.start(true)
	if err := w.writePrefix(); err != nil {
		return 0, err
	}
	return w.write(body)
}

func (w *writer) start(encoded bool) {
	if w.started {
		return
	}
	w.started = true
	if w.headers != nil {
		h := w.Header()
		// Trailer values can be supplied after WriteHeader. Retain those while
		// discarding later edits to ordinary response headers.
		for _, line := range w.headers.Values("Trailer") {
			for _, name := range strings.Split(line, ",") {
				name = http.CanonicalHeaderKey(strings.TrimSpace(name))
				if values, ok := h[name]; ok {
					w.headers[name] = values
				}
			}
		}
		for name, values := range h {
			if strings.HasPrefix(name, http.TrailerPrefix) {
				w.headers[name] = values
			}
		}
		clear(h)
		for name, values := range w.headers {
			h[name] = values
		}
		w.headers = nil
	}
	if w.code == 0 {
		w.code = http.StatusOK
	}
	if w.eligible() {
		varyEncoding(w.Header())
	}
	if encoded {
		h := w.Header()
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		for _, name := range []string{"Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
			h.Del(name)
		}
		if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
			if strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`) {
				h.Set("ETag", "W/"+etag)
			} else {
				h.Del("ETag")
			}
		}
		w.gz = w.pool.Get().(*gzip.Writer)
		w.gz.Reset(w.ResponseWriter)
	}
	w.ResponseWriter.WriteHeader(w.code)
}

func (w *writer) write(body []byte) (int, error) {
	if w.gz != nil {
		return w.gz.Write(body)
	}
	return w.ResponseWriter.Write(body)
}

func (w *writer) writePrefix() error {
	if len(w.prefix) == 0 {
		return nil
	}
	_, err := w.write(w.prefix)
	w.prefix = nil
	return err
}

func (w *writer) finish() error {
	if !w.started {
		w.start(false)
	}
	if err := w.writePrefix(); err != nil {
		return err
	}
	if w.gz != nil {
		return w.gz.Close()
	}
	return nil
}

func (w *writer) Flush() { _ = w.FlushError() }

func (w *writer) FlushError() error {
	if w.code == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.started {
		w.start(w.accept)
	}
	if err := w.writePrefix(); err != nil {
		return err
	}
	if w.gz != nil {
		if err := w.gz.Flush(); err != nil {
			return err
		}
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func varyEncoding(h http.Header) {
	for _, line := range h.Values("Vary") {
		for _, token := range strings.Split(line, ",") {
			if token = strings.TrimSpace(token); token == "*" || strings.EqualFold(token, "Accept-Encoding") {
				return
			}
		}
	}
	h.Add("Vary", "Accept-Encoding")
}

func directive(value, name string) bool {
	for _, item := range strings.Split(value, ",") {
		key, _, _ := strings.Cut(item, "=")
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return true
		}
	}
	return false
}

func acceptsGzip(lines []string) bool {
	var explicit, wildcard, identity float64
	explicit, wildcard, identity = -1, -1, -1
	for _, line := range lines {
		for _, item := range strings.Split(line, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(item), ";")
			q := 1.0
			if params != "" {
				key, value, ok := strings.Cut(strings.TrimSpace(params), "=")
				if !ok || !strings.EqualFold(key, "q") {
					q = 0
				} else if parsed, err := strconv.ParseFloat(value, 64); err != nil || parsed < 0 || parsed > 1 {
					q = 0
				} else {
					q = parsed
				}
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "gzip":
				explicit = q
			case "*":
				wildcard = q
			case "identity":
				identity = q
			}
		}
	}
	if explicit < 0 {
		explicit = wildcard
	}
	return explicit > 0 && explicit >= identity
}
