package health

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewSidecar_emptyAddr(t *testing.T) {
	t.Parallel()
	_, err := NewSidecar(SidecarConfig{
		Addr:    "",
		Version: "v1",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("expected error for empty Addr")
	}
	if !strings.Contains(err.Error(), "Addr") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSidecar_healthEndpoint(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	sc, err := NewSidecar(SidecarConfig{
		Addr:    addr,
		Version: "test-svc",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.ListenAndServe()
	}()

	defer func() {
		shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sc.Shutdown(shctx)
	}()

	var body string
	for i := 0; i < 50; i++ {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("unexpected health body: %q", body)
	}
}

func TestSidecar_optionalEndpoints(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	readiness := NewReadinessChecker("test-svc", true)
	readiness.Register("dep", func() CheckStatus { return CheckStatus{Status: "fail", Detail: "down"} })

	sc, err := NewSidecar(SidecarConfig{
		Addr:      addr,
		Version:   "test-svc",
		Readiness: readiness,
		Metrics: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("metrics ok"))
		}),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- sc.ListenAndServe()
	}()

	defer func() {
		shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sc.Shutdown(shctx)
	}()

	assertEventually := func(path string, wantStatus int, wantBody string) {
		t.Helper()
		for i := 0; i < 50; i++ {
			resp, err := http.Get("http://" + addr + path)
			if err == nil {
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == wantStatus && strings.Contains(string(body), wantBody) {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("endpoint %s did not return %d containing %q", path, wantStatus, wantBody)
	}

	assertEventually("/readiness", http.StatusServiceUnavailable, `"status":"not_ready"`)
	assertEventually("/metrics", http.StatusOK, "metrics ok")
}
