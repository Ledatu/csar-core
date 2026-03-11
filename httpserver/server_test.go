package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ledatu/csar-core/tlsx"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNew_Defaults(t *testing.T) {
	s, err := New(&Config{
		Addr:    ":0",
		Handler: http.NotFoundHandler(),
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", s.srv.ReadTimeout)
	}
	if s.srv.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", s.srv.WriteTimeout)
	}
	if s.srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", s.srv.IdleTimeout)
	}
	if s.srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want %d", s.srv.MaxHeaderBytes, 1<<20)
	}
	if s.shutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", s.shutdownTimeout)
	}
}

func TestNew_CustomTimeouts(t *testing.T) {
	s, err := New(&Config{
		Addr:            ":0",
		Handler:         http.NotFoundHandler(),
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     15 * time.Second,
		MaxHeaderBytes:  512,
		ShutdownTimeout: 3 * time.Second,
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.srv.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want 5s", s.srv.ReadTimeout)
	}
	if s.shutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 3s", s.shutdownTimeout)
	}
}

func TestNew_BadTLS(t *testing.T) {
	_, err := New(&Config{
		Addr:    ":0",
		Handler: http.NotFoundHandler(),
		TLS: &tlsx.ServerConfig{
			ClientCAFile: "/nonexistent/ca.pem",
		},
	}, testLogger())
	if err == nil {
		t.Fatal("expected error for bad TLS config")
	}
}

func TestListenAndServe_PlainHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	s, err := New(&Config{Addr: "127.0.0.1:0", Handler: mux}, testLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.srv.Addr = ln.Addr().String()
	ln.Close()

	go func() { _ = s.ListenAndServe() }()
	defer func() { _ = s.Shutdown(context.Background()) }()

	// Give server time to start.
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://%s/ping", s.srv.Addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Errorf("body = %q, want %q", body, "pong")
	}
}

func TestListenAndServe_TLS(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := generateCA(t)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caCert.Raw)
	serverCert, serverKey := generateLeaf(t, caCert, caKey, "127.0.0.1")
	certFile := writePEM(t, dir, "cert.pem", "CERTIFICATE", serverCert.Raw)
	keyFile := writeKeyPEM(t, dir, "key.pem", serverKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure-pong"))
	})

	s, err := New(&Config{
		Addr:    "127.0.0.1:0",
		Handler: mux,
		TLS: &tlsx.ServerConfig{
			CertFile:   certFile,
			KeyFile:    keyFile,
			MinVersion: "1.3",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s.srv.Addr = addr

	go func() { _ = s.ListenAndServe() }()
	defer func() { _ = s.Shutdown(context.Background()) }()

	time.Sleep(100 * time.Millisecond)

	pool, _ := tlsx.LoadCertPool(caFile)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/ping", addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure-pong" {
		t.Errorf("body = %q, want %q", body, "secure-pong")
	}
}

func TestRun_Cancellation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})

	s, err := New(&Config{
		Addr:            "127.0.0.1:0",
		Handler:         mux,
		ShutdownTimeout: 2 * time.Second,
	}, testLogger())
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.srv.Addr = ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestTLSConfig_Nil(t *testing.T) {
	s, _ := New(&Config{Addr: ":0", Handler: http.NotFoundHandler()}, testLogger())
	if s.TLSConfig() != nil {
		t.Error("expected nil TLSConfig for plain HTTP")
	}
}

// --- cert helpers (duplicated from tlsx_test; kept local to avoid export) ---

func generateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func generateLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(host)},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func writePEM(t *testing.T, dir, name, typ string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, _ := os.Create(path)
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: data}); err != nil {
		t.Fatalf("pem encode %s: %v", name, err)
	}
	return path
}

func writeKeyPEM(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, _ := x509.MarshalECPrivateKey(key)
	return writePEM(t, dir, name, "EC PRIVATE KEY", der)
}
