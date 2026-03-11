package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewServerTLSConfig_Defaults(t *testing.T) {
	tc, err := NewServerTLSConfig(ServerConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS12)
	}
	if tc.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tc.ClientAuth)
	}
}

func TestNewServerTLSConfig_LoadsCerts(t *testing.T) {
	certFile, keyFile := writeTempKeyPair(t)
	tc, err := NewServerTLSConfig(ServerConfig{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tc.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(tc.Certificates))
	}
}

func TestNewServerTLSConfig_HalfConfigured(t *testing.T) {
	_, err := NewServerTLSConfig(ServerConfig{CertFile: "cert.pem"})
	if err == nil {
		t.Fatal("expected error for cert without key")
	}
	_, err = NewServerTLSConfig(ServerConfig{KeyFile: "key.pem"})
	if err == nil {
		t.Fatal("expected error for key without cert")
	}
}

func TestNewServerTLSConfig_TLS13(t *testing.T) {
	tc, err := NewServerTLSConfig(ServerConfig{MinVersion: "1.3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS13)
	}
}

func TestNewServerTLSConfig_mTLS(t *testing.T) {
	caFile := writeTempCA(t)
	tc, err := NewServerTLSConfig(ServerConfig{ClientCAFile: caFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tc.ClientAuth)
	}
	if tc.ClientCAs == nil {
		t.Fatal("ClientCAs is nil")
	}
}

func TestNewServerTLSConfig_BadCAFile(t *testing.T) {
	_, err := NewServerTLSConfig(ServerConfig{ClientCAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestNewServerTLSConfig_InvalidPEM(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(f, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := NewServerTLSConfig(ServerConfig{ClientCAFile: f})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestNewClientTLSConfig_Defaults(t *testing.T) {
	tc, err := NewClientTLSConfig(ClientConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", tc.MinVersion, tls.VersionTLS12)
	}
	if tc.RootCAs != nil {
		t.Error("expected nil RootCAs for system default")
	}
}

func TestNewClientTLSConfig_WithCA(t *testing.T) {
	caFile := writeTempCA(t)
	tc, err := NewClientTLSConfig(ClientConfig{CAFile: caFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.RootCAs == nil {
		t.Fatal("expected non-nil RootCAs")
	}
}

func TestNewClientTLSConfig_WithClientCert(t *testing.T) {
	certFile, keyFile := writeTempKeyPair(t)
	tc, err := NewClientTLSConfig(ClientConfig{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tc.Certificates) != 1 {
		t.Fatalf("Certificates length = %d, want 1", len(tc.Certificates))
	}
}

func TestNewClientTLSConfig_BadCA(t *testing.T) {
	_, err := NewClientTLSConfig(ClientConfig{CAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestNewClientTLSConfig_BadKeyPair(t *testing.T) {
	_, err := NewClientTLSConfig(ClientConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"})
	if err == nil {
		t.Fatal("expected error for missing key pair")
	}
}

func TestNewClientTLSConfig_HalfConfigured(t *testing.T) {
	_, err := NewClientTLSConfig(ClientConfig{CertFile: "cert.pem"})
	if err == nil {
		t.Fatal("expected error for cert without key")
	}
	_, err = NewClientTLSConfig(ClientConfig{KeyFile: "key.pem"})
	if err == nil {
		t.Fatal("expected error for key without cert")
	}
}

func TestNewClientTLSConfig_ServerName(t *testing.T) {
	tc, err := NewClientTLSConfig(ClientConfig{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", tc.ServerName, "example.com")
	}
}

func TestLoadCertPool(t *testing.T) {
	caFile := writeTempCA(t)
	pool, err := LoadCertPool(caFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestMTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := generateCA(t)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caCert.Raw)

	serverCert, serverKey := generateLeaf(t, caCert, caKey, "localhost")
	serverCertFile := writePEM(t, dir, "server-cert.pem", "CERTIFICATE", serverCert.Raw)
	serverKeyFile := writeKeyPEM(t, dir, "server-key.pem", serverKey)

	clientCert, clientKey := generateLeaf(t, caCert, caKey, "client")
	clientCertFile := writePEM(t, dir, "client-cert.pem", "CERTIFICATE", clientCert.Raw)
	clientKeyFile := writeKeyPEM(t, dir, "client-key.pem", clientKey)

	serverTLS, err := NewServerTLSConfig(ServerConfig{
		CertFile:     serverCertFile,
		KeyFile:      serverKeyFile,
		ClientCAFile: caFile,
		MinVersion:   "1.3",
	})
	if err != nil {
		t.Fatalf("server TLS config: %v", err)
	}

	clientTLS, err := NewClientTLSConfig(ClientConfig{
		CAFile:   caFile,
		CertFile: clientCertFile,
		KeyFile:  clientKeyFile,
	})
	if err != nil {
		t.Fatalf("client TLS config: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// --- test helpers ---

func writeTempCA(t *testing.T) string {
	t.Helper()
	_, cert := generateCA(t)
	return writePEM(t, t.TempDir(), "ca.pem", "CERTIFICATE", cert.Raw)
}

func writeTempKeyPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	caKey, caCert := generateCA(t)
	cert, key := generateLeaf(t, caCert, caKey, "localhost")
	dir := t.TempDir()
	certFile = writePEM(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)
	keyFile = writeKeyPEM(t, dir, "key.pem", key)
	return
}

func generateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return key, cert
}

func generateLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

func writePEM(t *testing.T, dir, name, typ string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: data}); err != nil {
		t.Fatalf("pem encode %s: %v", name, err)
	}
	return path
}

func writeKeyPEM(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	return writePEM(t, dir, name, "EC PRIVATE KEY", der)
}
