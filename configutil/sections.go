package configutil

import (
	"fmt"
	"strings"
)

// HTTPServerSection is a reusable config block for HTTP server settings.
// Services embed this in their top-level config struct.
type HTTPServerSection struct {
	ListenAddr      string   `yaml:"listen_addr"`
	ReadTimeout     Duration `yaml:"read_timeout"`
	WriteTimeout    Duration `yaml:"write_timeout"`
	IdleTimeout     Duration `yaml:"idle_timeout"`
	MaxHeaderBytes  int      `yaml:"max_header_bytes"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
}

// Validate checks that required fields are present.
func (s HTTPServerSection) Validate() error {
	if s.ListenAddr == "" {
		return fmt.Errorf("configutil: http_server.listen_addr is required")
	}
	return nil
}

// TLSSection is a reusable config block for TLS settings.
type TLSSection struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
	MinVersion   string `yaml:"min_version"`
}

// Validate checks that cert and key are both present (or both absent)
// and that min_version is a recognized value.
func (s TLSSection) Validate() error {
	hasCert := s.CertFile != ""
	hasKey := s.KeyFile != ""
	if hasCert != hasKey {
		return fmt.Errorf("configutil: tls.cert_file and tls.key_file must both be set or both be empty")
	}
	if s.MinVersion != "" && s.MinVersion != "1.2" && s.MinVersion != "1.3" {
		return fmt.Errorf("configutil: tls.min_version must be \"1.2\" or \"1.3\", got %q", s.MinVersion)
	}
	return nil
}

// IsEnabled returns true if both cert and key paths are configured.
func (s TLSSection) IsEnabled() bool {
	return s.CertFile != "" && s.KeyFile != ""
}

// DatabaseSection is a reusable config block for database connections.
type DatabaseSection struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// Validate checks that a driver and DSN are provided.
func (s DatabaseSection) Validate() error {
	if s.Driver == "" {
		return fmt.Errorf("configutil: database.driver is required")
	}
	if s.DSN == "" {
		return fmt.Errorf("configutil: database.dsn is required")
	}
	return nil
}

// LogSection is a reusable config block for structured logging.
type LogSection struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
	Redact bool   `yaml:"redact"`
}

// Validate checks that level and format are recognized values.
func (s LogSection) Validate() error {
	if s.Level != "" {
		switch strings.ToLower(s.Level) {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("configutil: log.level must be debug|info|warn|error, got %q", s.Level)
		}
	}
	if s.Format != "" {
		switch strings.ToLower(s.Format) {
		case "json", "text":
		default:
			return fmt.Errorf("configutil: log.format must be json|text, got %q", s.Format)
		}
	}
	return nil
}

// HealthSection is a reusable config block for health probe endpoints.
type HealthSection struct {
	Enabled       bool   `yaml:"enabled"`
	LivenessPath  string `yaml:"liveness_path"`
	ReadinessPath string `yaml:"readiness_path"`
}

// WithDefaults returns a copy with standard defaults applied.
func (s HealthSection) WithDefaults() HealthSection {
	if s.LivenessPath == "" {
		s.LivenessPath = "/health"
	}
	if s.ReadinessPath == "" {
		s.ReadinessPath = "/readiness"
	}
	return s
}

// ProbeSidecarSection configures the plain HTTP health/readiness/metrics sidecar.
// It intentionally uses health_addr even when metrics are also exposed there.
type ProbeSidecarSection struct {
	Addr string `yaml:"health_addr"`
}

// WithDefault returns a copy with the given default listen address applied.
func (s ProbeSidecarSection) WithDefault(addr string) ProbeSidecarSection {
	if s.Addr == "" {
		s.Addr = addr
	}
	return s
}
