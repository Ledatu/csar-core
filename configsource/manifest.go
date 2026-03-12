package configsource

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Manifest is the top-level artifact-pointer document. It describes how each
// service should acquire its configuration from an external provider (S3,
// file, HTTP, etc.). The manifest itself is fetched via a ConfigSource and
// then resolved into per-service config payloads.
type Manifest struct {
	ManifestVersion string                     `json:"manifest_version"`
	Environment     string                     `json:"environment,omitempty"`
	UpdatedAt       string                     `json:"updated_at,omitempty"`
	TraceID         string                     `json:"trace_id,omitempty"`
	Services        map[string]ServiceManifest `json:"services"`
}

// ServiceManifest is one service's entry inside a Manifest.
type ServiceManifest struct {
	Version string         `json:"version"`
	Active  *bool          `json:"active,omitempty"` // nil is treated as true
	Config  ConfigResource `json:"config"`
}

// IsActive reports whether the service entry is considered active.
// A nil Active pointer is treated as true.
func (sm *ServiceManifest) IsActive() bool {
	return sm.Active == nil || *sm.Active
}

// ConfigResource describes where and how to fetch a single config artifact.
type ConfigResource struct {
	Provider string            `json:"provider"`           // "s3", "file", "http"
	Path     string            `json:"path"`               // object key, file path, or URL path
	Bucket   string            `json:"bucket,omitempty"`   // S3 only
	Region   string            `json:"region,omitempty"`   // S3 only
	Endpoint string            `json:"endpoint,omitempty"` // S3 endpoint or HTTP base URL override
	Checksum *ChecksumInfo     `json:"checksum,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"` // HTTP only
	Meta     map[string]string `json:"meta,omitempty"`    // extensible metadata
}

// ChecksumInfo carries a hash algorithm and expected digest value.
type ChecksumInfo struct {
	Algorithm string `json:"algorithm"` // "sha256"
	Value     string `json:"value"`
}

// supportedManifestVersions lists the manifest_version values we can parse.
var supportedManifestVersions = map[string]bool{
	"1":   true,
	"1.0": true,
	"1.1": true,
}

// ParseManifest decodes a JSON manifest and validates its structure.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest JSON: %w", err)
	}

	if !supportedManifestVersions[m.ManifestVersion] {
		return nil, fmt.Errorf("unsupported manifest_version %q; supported: 1, 1.0, 1.1", m.ManifestVersion)
	}

	if len(m.Services) == 0 {
		return nil, fmt.Errorf("manifest contains no service entries")
	}

	for name := range m.Services {
		svc := m.Services[name]
		if svc.Version == "" {
			return nil, fmt.Errorf("service %q: version is required", name)
		}
		if err := svc.Config.Validate(); err != nil {
			return nil, fmt.Errorf("service %q: %w", name, err)
		}
	}

	return &m, nil
}

// LookupService finds a service entry by name and verifies it is active.
func (m *Manifest) LookupService(name string) (*ServiceManifest, error) {
	svc, ok := m.Services[name]
	if !ok {
		available := make([]string, 0, len(m.Services))
		for k := range m.Services {
			available = append(available, k)
		}
		return nil, fmt.Errorf("service %q not found in manifest; available: [%s]",
			name, strings.Join(available, ", "))
	}

	if !svc.IsActive() {
		return nil, fmt.Errorf("service %q is marked inactive in manifest (version %s)", name, svc.Version)
	}

	return &svc, nil
}

// Validate checks that the ConfigResource has the required fields for its
// declared provider.
func (cr *ConfigResource) Validate() error {
	switch cr.Provider {
	case "s3":
		if cr.Bucket == "" {
			return fmt.Errorf("config provider %q requires bucket", cr.Provider)
		}
		if cr.Path == "" {
			return fmt.Errorf("config provider %q requires path", cr.Provider)
		}
	case "file":
		if cr.Path == "" {
			return fmt.Errorf("config provider %q requires path", cr.Provider)
		}
	case "http":
		if cr.Path == "" {
			return fmt.Errorf("config provider %q requires path (URL)", cr.Provider)
		}
	case "":
		return fmt.Errorf("config provider is required")
	default:
		return fmt.Errorf("unsupported config provider %q; supported: s3, file, http", cr.Provider)
	}

	if cr.Checksum != nil {
		if cr.Checksum.Algorithm == "" {
			return fmt.Errorf("checksum.algorithm is required when checksum is present")
		}
		if cr.Checksum.Value == "" {
			return fmt.Errorf("checksum.value is required when checksum is present")
		}
		if cr.Checksum.Algorithm != "sha256" {
			return fmt.Errorf("unsupported checksum algorithm %q; supported: sha256", cr.Checksum.Algorithm)
		}
	}

	return nil
}
