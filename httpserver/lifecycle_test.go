package httpserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func waitServing(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !s.IsServing() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !s.IsServing() {
		t.Fatal("server never reached its accept loop")
	}
}

func TestLifecycleReadyOnlyWhileServing(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := New(&Config{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if s.IsServing() {
		t.Fatal("unstarted server reported ready")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	waitServing(t, s)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		r, requestErr := http.Get("http://" + ln.Addr().String())
		if requestErr == nil {
			_ = r.Body.Close()
		}
	}()
	<-entered
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- s.Shutdown(context.Background()) }()
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve error = %v", err)
	}
	if s.IsServing() {
		t.Fatal("draining server reported ready with a request still in flight")
	}
	close(release)
	<-requestDone
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleBindFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	s, err := New(&Config{Addr: ln.Addr().String()}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ListenAndServe(); err == nil || s.IsServing() {
		t.Fatalf("bind failure: err=%v ready=%v", err, s.IsServing())
	}
}

func TestLifecycleListenerFailureAndShutdownBeforeStart(t *testing.T) {
	for _, shutdownFirst := range []bool{false, true} {
		s, err := New(&Config{}, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if shutdownFirst {
			if err := s.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() { done <- s.Serve(ln) }()
		if !shutdownFirst {
			waitServing(t, s)
			_ = ln.Close()
		}
		if err := <-done; err == nil || s.IsServing() {
			t.Fatalf("listener failure: err=%v ready=%v", err, s.IsServing())
		}
	}
}
