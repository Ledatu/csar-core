// Package tlsx provides helpers for building safe tls.Config values
// for both server and client sides, including mTLS support.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// ServerConfig describes the TLS settings for a server listener.
type ServerConfig struct {
	CertFile     string // path to PEM-encoded server certificate
	KeyFile      string // path to PEM-encoded server private key
	ClientCAFile string // path to PEM-encoded CA for client verification; empty disables mTLS
	MinVersion   string // "1.2" (default) or "1.3"
}

// ClientConfig describes the TLS settings for an outbound client connection.
type ClientConfig struct {
	CAFile             string // path to PEM-encoded CA for server verification; empty uses system roots
	CertFile           string // path to PEM-encoded client certificate; empty disables client auth
	KeyFile            string // path to PEM-encoded client private key
	ServerName         string // expected server name for verification
	InsecureSkipVerify bool   // skip server certificate verification (dev only)
}

// NewServerTLSConfig builds a tls.Config suitable for an HTTPS or gRPC server.
// If CertFile and KeyFile are provided, the certificate is loaded into the
// returned config. If ClientCAFile is set, mutual TLS is enforced.
//
// It is an error to set only one of CertFile or KeyFile.
func NewServerTLSConfig(cfg ServerConfig) (*tls.Config, error) {
	if err := validatePair(cfg.CertFile, cfg.KeyFile, "server cert_file", "server key_file"); err != nil {
		return nil, err
	}

	tc := &tls.Config{
		MinVersion: parseMinVersion(cfg.MinVersion),
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: loading server key pair: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	if cfg.ClientCAFile != "" {
		pool, err := LoadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: loading client CA: %w", err)
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tc, nil
}

// NewClientTLSConfig builds a tls.Config suitable for an outbound HTTPS or gRPC client.
//
// It is an error to set only one of CertFile or KeyFile.
func NewClientTLSConfig(cfg ClientConfig) (*tls.Config, error) {
	if err := validatePair(cfg.CertFile, cfg.KeyFile, "client cert_file", "client key_file"); err != nil {
		return nil, err
	}

	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CAFile != "" {
		pool, err := LoadCertPool(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: loading CA: %w", err)
		}
		tc.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: loading client key pair: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	return tc, nil
}

// NewHTTPTransport builds an *http.Transport with TLS configured per cfg.
// It clones http.DefaultTransport to preserve sensible connection-pool defaults.
func NewHTTPTransport(cfg ClientConfig) (*http.Transport, error) {
	tlsCfg, err := NewClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return tr, nil
}

// LoadCertPool reads a PEM file and returns a certificate pool.
func LoadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s contains no valid PEM certificates", path)
	}
	return pool, nil
}

func parseMinVersion(v string) uint16 {
	if v == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func validatePair(a, b, aName, bName string) error {
	if (a == "") != (b == "") {
		return fmt.Errorf("tlsx: %s and %s must both be set or both be empty", aName, bName)
	}
	return nil
}
