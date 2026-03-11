package httpmiddleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChain_Order(t *testing.T) {
	var order []string

	a := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "A-before")
			next.ServeHTTP(w, r)
			order = append(order, "A-after")
		})
	}
	b := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "B-before")
			next.ServeHTTP(w, r)
			order = append(order, "B-after")
		})
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	Chain(a, b)(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	want := "A-before,B-before,handler,B-after,A-after"
	got := strings.Join(order, ",")
	if got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
}

func TestChain_Empty(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	Chain()(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if !called {
		t.Error("inner handler not called")
	}
}

func TestRequestID_Generates(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRequestID) == "" {
			t.Error("expected request ID to be set on inbound request")
		}
	})).ServeHTTP(rec, req)

	if rec.Header().Get(headerRequestID) == "" {
		t.Error("expected request ID in response header")
	}
}

func TestRequestID_PreservesExisting(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(headerRequestID, "existing-id")

	RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRequestID) != "existing-id" {
			t.Errorf("request ID = %q, want %q", r.Header.Get(headerRequestID), "existing-id")
		}
	})).ServeHTTP(rec, req)

	if rec.Header().Get(headerRequestID) != "existing-id" {
		t.Errorf("response request ID = %q, want %q", rec.Header().Get(headerRequestID), "existing-id")
	}
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/test", nil)

	AccessLog(logger)(inner).ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "POST") {
		t.Error("log missing method")
	}
	if !strings.Contains(logOutput, "/api/test") {
		t.Error("log missing path")
	}
	if !strings.Contains(logOutput, "201") {
		t.Errorf("log missing status code 201: %s", logOutput)
	}
}

func TestRecover_NoPanic(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	Recover(logger)(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRecover_Panic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	rec := httptest.NewRecorder()
	Recover(logger)(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(buf.String(), "test panic") {
		t.Error("panic value not logged")
	}
}

func TestTimeout_SetsContext(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("expected deadline on context")
		}
		if time.Until(deadline) > 5*time.Second {
			t.Errorf("deadline too far: %v", time.Until(deadline))
		}
		_, _ = w.Write([]byte("ok"))
	})

	rec := httptest.NewRecorder()
	Timeout(5*time.Second)(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestTimeout_Returns503_WhenExceeded(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte("should not arrive"))
		case <-r.Context().Done():
		}
	})

	rec := httptest.NewRecorder()
	Timeout(50*time.Millisecond)(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestTimeout_NonCooperativeHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("too late"))
	})

	rec := httptest.NewRecorder()
	Timeout(50*time.Millisecond)(inner).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (non-cooperative handler should still be timed out)", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestMaxBodySize(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("expected error reading oversized body")
		}
	})

	body := strings.NewReader(strings.Repeat("x", 1024))
	req := httptest.NewRequest("POST", "/", body)
	rec := httptest.NewRecorder()

	MaxBodySize(10)(inner).ServeHTTP(rec, req)
}

func TestMaxBodySize_UnderLimit(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("body = %q, want %q", data, "hello")
		}
	})

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	rec := httptest.NewRecorder()

	MaxBodySize(1024)(inner).ServeHTTP(rec, req)
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() { f.flushed = true }

func TestAccessLog_PreservesFlusher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fr := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	AccessLog(logger)(inner).ServeHTTP(fr, httptest.NewRequest("GET", "/", nil))
	if !fr.flushed {
		t.Error("Flusher interface was not preserved through the recorder")
	}
}

func TestResponseRecorder_DefaultStatus(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	if rec.statusCode != http.StatusOK {
		t.Errorf("default status = %d, want %d", rec.statusCode, http.StatusOK)
	}
}

func TestResponseRecorder_CapturesWriteHeader(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	rec.WriteHeader(http.StatusNotFound)
	if rec.statusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.statusCode, http.StatusNotFound)
	}
}

func TestResponseRecorder_OnlyFirstWriteHeader(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: httptest.NewRecorder(), statusCode: http.StatusOK}
	rec.WriteHeader(http.StatusNotFound)
	rec.WriteHeader(http.StatusBadGateway)
	if rec.statusCode != http.StatusNotFound {
		t.Errorf("status = %d, want first value %d", rec.statusCode, http.StatusNotFound)
	}
}
