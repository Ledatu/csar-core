package stsclient

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/tlsx"
)

const stsInternalTimeout = 30 * time.Second

// JWTKeysConfig points to the PEM files for the service's signing key pair.
type JWTKeysConfig struct {
	PrivateKeyFile string `yaml:"private_key_file"`
	PublicKeyFile  string `yaml:"public_key_file"`
}

// RouterTLSConfig configures TLS for outbound calls to the csar router.
type RouterTLSConfig struct {
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// STSTLSConfig configures TLS (including mTLS client certs) for the STS
// token-exchange endpoint on csar-authn.
type STSTLSConfig struct {
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// ServiceAuthConfig is the shared configuration block for any service that
// authenticates to the csar router via STS token exchange. It combines the
// STS parameters, JWT signing keys, and TLS material for both STS and router
// connections into a single struct suitable for embedding in YAML configs.
type ServiceAuthConfig struct {
	RouterBaseURL     string          `yaml:"router_base_url"`
	STSEndpoint       string          `yaml:"sts_endpoint"`
	Audience          string          `yaml:"audience"`
	ServiceName       string          `yaml:"service_name"`
	AssertionAudience string          `yaml:"assertion_audience"`
	RouterTimeout     time.Duration   `yaml:"router_timeout"`
	JWT               JWTKeysConfig   `yaml:"jwt"`
	RouterTLS         RouterTLSConfig `yaml:"router_tls"`
	STSTLS            STSTLSConfig    `yaml:"sts_tls"`
}

// requiredFields lists what must be present for a fully-configured block.
var requiredFields = []struct {
	name string
	get  func(*ServiceAuthConfig) string
}{
	{"router_base_url", func(c *ServiceAuthConfig) string { return c.RouterBaseURL }},
	{"sts_endpoint", func(c *ServiceAuthConfig) string { return c.STSEndpoint }},
	{"audience", func(c *ServiceAuthConfig) string { return c.Audience }},
	{"service_name", func(c *ServiceAuthConfig) string { return c.ServiceName }},
	{"assertion_audience", func(c *ServiceAuthConfig) string { return c.AssertionAudience }},
	{"jwt.private_key_file", func(c *ServiceAuthConfig) string { return c.JWT.PrivateKeyFile }},
	{"jwt.public_key_file", func(c *ServiceAuthConfig) string { return c.JWT.PublicKeyFile }},
}

// Validate enforces all-or-nothing semantics on ServiceAuthConfig.
// If every required field is empty the block is considered unconfigured and
// nil is returned. If every required field is present nil is also returned.
// A partially-filled block returns an error listing the missing fields.
func (c *ServiceAuthConfig) Validate() error {
	var filled, missing []string
	for _, f := range requiredFields {
		if f.get(c) != "" {
			filled = append(filled, f.name)
		} else {
			missing = append(missing, f.name)
		}
	}
	if len(filled) == 0 {
		return nil
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("service_auth: partially configured — missing: %s", strings.Join(missing, ", "))
}

// IsConfigured reports whether the block contains any STS configuration.
// Call Validate first to ensure the block is not partially filled.
func (c *ServiceAuthConfig) IsConfigured() bool {
	return c.STSEndpoint != ""
}

// RouterClient is an authenticated HTTP client pre-configured for calling
// endpoints through the csar router with STS Bearer tokens.
type RouterClient struct {
	Client  *http.Client
	BaseURL string
}

// NewRouterClient loads key material, builds TLS transports for STS and
// the router, creates a TokenSource, and returns a ready-to-use RouterClient.
// cfg.RouterTimeout is applied to the returned *http.Client; zero means no
// timeout. The STS internal HTTP client always uses a 30s timeout.
func NewRouterClient(cfg *ServiceAuthConfig, logger *slog.Logger) (*RouterClient, error) {
	if logger == nil {
		logger = slog.Default()
	}

	kp, err := jwtx.LoadKeyPairFromPEM(cfg.JWT.PrivateKeyFile, cfg.JWT.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("service auth: loading jwt keys: %w", err)
	}

	stsTransport, err := tlsx.NewHTTPTransport(tlsx.ClientConfig{
		CAFile:   cfg.STSTLS.CAFile,
		CertFile: cfg.STSTLS.CertFile,
		KeyFile:  cfg.STSTLS.KeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("service auth: sts transport: %w", err)
	}

	routerTransport, err := tlsx.NewHTTPTransport(tlsx.ClientConfig{
		CAFile:     cfg.RouterTLS.CAFile,
		ServerName: cfg.RouterTLS.ServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("service auth: router transport: %w", err)
	}

	ts, err := New(&Config{
		STSEndpoint:       cfg.STSEndpoint,
		Audience:          cfg.Audience,
		ServiceName:       cfg.ServiceName,
		AssertionAudience: cfg.AssertionAudience,
		KeyPair:           kp,
		AssertionTTL:      4 * time.Minute,
		HTTPClient: &http.Client{
			Transport: stsTransport,
			Timeout:   stsInternalTimeout,
		},
		Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("service auth: token source: %w", err)
	}

	client := &http.Client{
		Transport: ts.Transport(newRetryTransport(routerTransport, logger)),
	}
	if cfg.RouterTimeout > 0 {
		client.Timeout = cfg.RouterTimeout
	}

	return &RouterClient{
		Client:  client,
		BaseURL: cfg.RouterBaseURL,
	}, nil
}
