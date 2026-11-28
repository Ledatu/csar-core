package compress

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNegotiationAndRepresentation(t *testing.T) {
	body := []byte(`{"data":"` + strings.Repeat("abc", 2048) + `"}`)
	for _, tc := range []struct {
		encoding string
		gzip     bool
	}{
		{"", false}, {"identity", false}, {"br", false}, {"gzip", true}, {"GZip", true}, {"br, gzip;q=0.5", true},
		{"gzip;q=0", false}, {"*;q=1, gzip;q=0", false}, {"*;q=0.5", true}, {"gzip;q=bad", false},
		{"gzip;q=NaN", false}, {"gzip;q=2", false}, {"gzip;q=-1", false}, {"gzip;q=0.5, identity;q=1", false},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("Content-Digest", "old-digest")
				w.Header().Set("Vary", "Origin")
				_, _ = w.Write(body)
			}), Options{})
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept-Encoding", tc.encoding)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if got := rec.Header().Get("Content-Encoding"); (got == "gzip") != tc.gzip {
				t.Fatalf("encoding=%q", got)
			}
			decoded := rec.Body.Bytes()
			if tc.gzip {
				if rec.Header().Get("Content-Length") != "" || rec.Header().Get("ETag") != `W/"original"` || rec.Header().Get("Content-Digest") != "" {
					t.Fatal(rec.Header())
				}
				zr, err := gzip.NewReader(bytes.NewReader(decoded))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err = io.ReadAll(zr)
				if err != nil {
					t.Fatal(err)
				}
				_ = zr.Close()
			} else if rec.Header().Get("ETag") != `"original"` {
				t.Fatal("identity validator changed")
			}
			if !bytes.Equal(decoded, body) {
				t.Fatal("body changed")
			}
			if strings.Join(rec.Header().Values("Vary"), ",") != "Origin,Accept-Encoding" {
				t.Fatal(rec.Header().Values("Vary"))
			}
		})
	}
}

func TestFactoryPreservesAllUpstreamEncodingLines(t *testing.T) {
	wrap := GzipMiddleware(Options{})
	for _, coding := range []string{"gzip", "br", "identity"} {
		payload := bytes.Repeat([]byte("already-encoded-fixture"), 512)
		h := wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header()["Content-Encoding"] = []string{"", "  ", coding}
			_, _ = w.Write(payload)
		}))
		for range 2 {
			req := httptest.NewRequest(http.MethodGet, "/arbitrary-installation", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if !bytes.Equal(rec.Body.Bytes(), payload) || strings.Join(rec.Header().Values("Content-Encoding"), ",") != ",  ,"+coding {
				t.Fatal("existing encoding was transformed", rec.Header())
			}
		}
	}
}

func TestBypasses(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		status       int
		headers      http.Header
		request      http.Header
		small        bool
	}{
		{name: "small", small: true}, {name: "head", method: "HEAD"}, {name: "range-request", request: http.Header{"Range": {"bytes=0-1"}}},
		{name: "partial", status: 206}, {name: "empty", status: 204}, {name: "error", status: 500},
		{name: "already-gzip", headers: http.Header{"Content-Encoding": {"gzip"}}},
		{name: "already-br", headers: http.Header{"Content-Encoding": {"br"}}},
		{name: "no-transform", headers: http.Header{"Cache-Control": {"public, no-transform"}}},
		{name: "request-no-transform", request: http.Header{"Cache-Control": {"no-transform"}}},
		{name: "no-store", headers: http.Header{"Cache-Control": {"no-store"}}},
		{name: "cookie", headers: http.Header{"Set-Cookie": {"session=opaque"}}},
		{name: "sse", headers: http.Header{"Content-Type": {"text/event-stream"}}},
		{name: "binary", headers: http.Header{"Content-Type": {"application/octet-stream"}}},
		{name: "content-range", headers: http.Header{"Content-Range": {"bytes 0-1/1000"}}},
		{name: "upgrade", request: http.Header{"Upgrade": {"websocket"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("a"), 4096)
			if tc.small {
				payload = []byte("{}")
			}
			h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				for k, v := range tc.headers {
					w.Header()[k] = v
				}
				code := tc.status
				if code == 0 {
					code = 200
				}
				w.WriteHeader(code)
				_, _ = w.Write(payload)
			}), Options{})
			method := tc.method
			if method == "" {
				method = "GET"
			}
			req := httptest.NewRequest(method, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			for k, v := range tc.request {
				req.Header[k] = v
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if !bytes.Equal(rec.Body.Bytes(), payload) {
				t.Fatal("bypass bytes changed")
			}
			if rec.Header().Get("Content-Encoding") != tc.headers.Get("Content-Encoding") {
				t.Fatal("bypass encoding changed")
			}
		})
	}
}

func TestFlushPrioritizesStreaming(t *testing.T) {
	for _, size := range []int{5, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			rec := httptest.NewRecorder()
			payload := strings.Repeat("x", size)
			h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, payload)
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Fatal(err)
				}
				if !rec.Flushed || rec.Body.Len() == 0 {
					t.Fatal("flush held bytes until handler returned")
				}
				if rec.Header().Get("Content-Encoding") != "gzip" {
					t.Fatal("flush did not commit negotiated gzip")
				}
			}), Options{})
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			h.ServeHTTP(rec, req)
		})
	}
}

func TestNativeGzipStreamingAndTrailers(t *testing.T) {
	release := make(chan struct{})
	h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Trailer", "X-Complete")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "tail")
		w.Header().Set("X-Complete", "yes")
	}), Options{})
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer close(release)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !resp.Uncompressed || resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("Go transport did not decode gzip")
	}
	prefix := make([]byte, 4096)
	if _, err = io.ReadFull(resp.Body, prefix); err != nil {
		t.Fatal(err)
	}
	release <- struct{}{}
	tail, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "tail" || resp.Trailer.Get("X-Complete") != "yes" {
		t.Fatalf("tail=%q trailers=%v", tail, resp.Trailer)
	}
}

func TestVaryAlreadyIncludesEncoding(t *testing.T) {
	for _, vary := range []string{"*", "Origin, accept-encoding"} {
		h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Vary", vary)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, strings.Repeat("x", 1024))
		}), Options{})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		h.ServeHTTP(rec, req)
		if len(rec.Header().Values("Vary")) != 1 || rec.Header().Get("Vary") != vary {
			t.Fatal(rec.Header())
		}
	}
}

type discardWriter struct{ h http.Header }

func (w *discardWriter) Header() http.Header       { return w.h }
func (*discardWriter) WriteHeader(int)             {}
func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func BenchmarkGzip(b *testing.B) {
	for _, size := range []int{1 << 20, 10 << 20} {
		for _, encoding := range []string{"identity", "gzip"} {
			b.Run(fmt.Sprintf("bytes%d-%s", size, encoding), func(b *testing.B) {
				payload := bytes.Repeat([]byte(`{"id":123456,"price":123.45},`), size/27+1)
				payload = payload[:size]
				h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(payload)
				}), Options{})
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Accept-Encoding", encoding)
				w := &discardWriter{h: make(http.Header)}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					clear(w.h)
					h.ServeHTTP(w, req)
				}
			})
		}
	}
}

func TestFrozenHeadersAndSmallResponseTrailers(t *testing.T) {
	h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Trailer", "X-Complete")
		w.Header().Set("X-Frozen", "original")
		w.WriteHeader(200)
		w.Header().Set("X-Frozen", "late")
		_, _ = io.WriteString(w, "{}")
		w.Header().Set("X-Complete", "yes")
	}), Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.Header.Get("X-Frozen") != "original" || resp.Trailer.Get("X-Complete") != "yes" {
		t.Fatal(resp.Header, resp.Trailer)
	}
}

func TestSeparateNoTransformHeader(t *testing.T) {
	h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Cache-Control", "public")
		w.Header().Add("Cache-Control", "no-transform")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}), Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("no-transform ignored")
	}
}

type failingWriter struct {
	h    http.Header
	fail bool
}

func (w *failingWriter) Header() http.Header { return w.h }
func (*failingWriter) WriteHeader(int)       {}
func (w *failingWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func TestReportsFinalizationError(t *testing.T) {
	target := &failingWriter{h: make(http.Header)}
	var observed error
	h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
		target.fail = true
	}), Options{OnError: func(err error) { observed = err }})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(target, req)
	if observed == nil {
		t.Fatal("finalization error lost")
	}
}

func TestPrefixBound(t *testing.T) {
	h := Gzip(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		cw := w.(*writer)
		for range 2000 {
			_, _ = io.WriteString(w, "a")
			if len(cw.prefix) >= 1024 {
				t.Fatalf("prefix grew to %d bytes", len(cw.prefix))
			}
		}
	}), Options{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(httptest.NewRecorder(), req)
}
